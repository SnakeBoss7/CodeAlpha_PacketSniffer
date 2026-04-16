from scapy.all import sniff, wrpcap
from datetime import datetime
import argparse
from collections import defaultdict
import socket
# proto counter
proto_count = defaultdict(int)

# ip counter
src_counter = defaultdict(int)
dst_counter = defaultdict(int)

# Column widths
W_TIME  = 20
W_PROTO = 6
W_IP    = 45
W_PORTS = 24
W_DIR = 10

#port mapping 
port_map = {
    80:"HTTP",
    443:"HTTPS",
    21:"FTP",
    22:"SSH",
    23:"Telnet",
    25:"SMTP",
    110:"POP3",
    53:"DNS",
    445:"SMB",
    3389:"RDP",
}

#get ipv4 and ipv6  address 
def get_ipv4():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # doesn't actually send data
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_ipv6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None

    
    
def snifferUi():
    print("================================================")
    print("Starting sniffer")
    print("================================================\n")
    print("-----------------Sniffer Settings---------------")
    print(f"Interface: {args.iface}")
    print(f"Count: {args.count}")
    if args.output:
        print(f"Output: {args.output}")
    print("------------------------------------------------\n")
    
    HDR = (
        f"{'TIME':<{W_TIME}}"
        f"{'PROTO':<{W_PROTO}}"
        f"{'SRC_IP':<{W_IP}}"
        f"{'DST_IP':<{W_IP}}"
        f"{'PORTS':<{W_PORTS}}"
        f"{'DIRECTION':<{W_DIR}}"
    )
    SEP = "─" * len(HDR)
    print(SEP)
    print(HDR)
    print(SEP)
def networkSniffingSummary():
    print("--------------Summary of the network sniffing------------------")
    total_count = 0
    for proto in proto_count:
        total_count+=proto_count[proto]
    for proto in proto_count:
        print(f"{proto} count : {proto_count[proto]} | {proto_count[proto]/total_count*100:.2f}%")

    print("\n--------------Top 5 most active source IPs--------------")
    for ip, count in sorted(src_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {ip} : {count}")
    print("\n--------------Top 5 most active destination IPs--------------")
    for ip, count in sorted(dst_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {ip} : {count}")

def packetAnalysis(packet):
    # print(packet.show())
    sport = None
    dport = None
    now   = str(datetime.now().time())
    proto = "-"
    src   = "-"
    dst   = "-"
    ports = "-"

    # Protocol
    
    # print(f"{packet.show()} data")

    ## TRANSPORT LAYER
    if packet.haslayer("TCP"):
        proto = "TCP"
        proto_count["TCP"]+=1
        try:
            sport = int(packet["TCP"].sport)
            dport = int(packet["TCP"].dport)
        except Exception:
            ports = "-"
    elif packet.haslayer("UDP"):
        if packet.haslayer("DNS"):
            proto_count["DNS"]+=1
            proto="DNS"
        else:
            proto_count["UDP"]+=1
            proto="UDP"
        try:
            sport = int(packet["UDP"].sport)
            dport = int(packet["UDP"].dport)

        except Exception:
            ports = "-"
    elif packet.haslayer("ICMP"):
        proto = "ICMP"
        proto_count["ICMP"]+=1
        try:
            sport = int(packet["ICMP"].sport)
            dport = int(packet["ICMP"].dport)
        except Exception:
            ports = "-"

    if sport in port_map:
        sport = f"{port_map[sport]}({sport})"
    if dport in port_map:
        dport = f"{port_map[dport]}({dport})"
    ports = f"{sport} -> {dport}"

    # IPv6
    ## NETWORK LAYER
    if packet.haslayer("IPv6"):
        src = str(packet["IPv6"].src)
        src_counter[src]+=1
        dst = str(packet["IPv6"].dst)
        dst_counter[dst]+=1


    # IPv4
    elif packet.haslayer("IP"):
        src = str(packet["IP"].src)
        src_counter[src]+=1
        dst = str(packet["IP"].dst)
        dst_counter[dst]+=1
    elif packet.haslayer("ARP"):
        src = str(packet["ARP"].psrc)
        src_counter[src]+=1
        dst = str(packet["ARP"].pdst)
        dst_counter[dst]+=1
        proto="ARP"
        proto_count["ARP"]+=1

    if src == get_ipv4() or src == get_ipv6():
        direction = "OUTBOUND"
    elif dst == get_ipv4() or dst == get_ipv6():
        direction = "INBOUND"
    elif src == dst:
        direction = "LOCAL"
    else:
        direction="EXTERNAL"
        
    print(
        f"{now:<{W_TIME}}"
        f"{proto:<{W_PROTO}}"
        f"{src:<{W_IP}}"
        f"{dst:<{W_IP}}"
        f"{ports:<{W_PORTS}}"
        f"{direction:<{W_DIR}}"
    )

def startSniffing(iface,pack_count,output,BPFfilter,summary):
    try:
        snifferUi()
        packets = sniff(
        count=pack_count,
        iface=iface,
        filter=BPFfilter,
        store=True,
        prn=packetAnalysis
        )
        print("Sniffer stopped.")
        if args.summary:
            networkSniffingSummary()
    except Exception as e:
        print(e)
    if output:
        wrpcap(f"{output}.pcap", packets)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("--count",  type=int, default=10,     help="Number of packets to capture")
    parser.add_argument("--iface",  type=str, default="Wi-Fi",help="Interface to capture on")
    parser.add_argument("--output", type=str, default="",       help="Output .pcap file name")
    parser.add_argument("--filter", type=str, default="",     help="BPF filter string")
    parser.add_argument("--summary",action="store_true",      help="Show summary after capture")
    args = parser.parse_args()

    startSniffing(args.iface,args.count,args.output,args.filter,args.summary)




