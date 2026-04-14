from scapy.all import sniff, wrpcap
from datetime import datetime
import argparse
# Column widths
W_TIME  = 20
W_PROTO = 6
W_IP    = 45
W_PORTS = 16

def packetAnalysis(packet):
    # print(packet.show())
    now   = str(datetime.now().time())
    proto = "-"
    src   = "-"
    dst   = "-"
    ports = "-"

    # Protocol
    if packet.haslayer("TCP"):
        proto = "TCP"
        try:
            sport = int(packet["TCP"].sport)
            dport = int(packet["TCP"].dport)
            ports = f"{sport}->{dport}"
        except Exception:
            ports = "-"
    elif packet.haslayer("UDP"):
        proto = "UDP"
        try:
            sport = int(packet["UDP"].sport)
            dport = int(packet["UDP"].dport)
            ports = f"{sport}->{dport}"
        except Exception:
            ports = "-"
    elif packet.haslayer("ICMP"):
        proto = "ICMP"
        try:
            sport = int(packet["ICMP"].sport)
            dport = int(packet["ICMP"].dport)
            ports = f"{sport}->{dport}"
        except Exception:
            ports = "-"


    # IPv6
    if packet.haslayer("IPv6"):
        src = str(packet["IPv6"].src)
        dst = str(packet["IPv6"].dst)


    # IPv4
    elif packet.haslayer("IP"):
        src = str(packet["IP"].src)
        dst = str(packet["IP"].dst)


    print(
        f"{now:<{W_TIME}}"
        f"{proto:<{W_PROTO}}"
        f"{src:<{W_IP}}"
        f"{dst:<{W_IP}}"
        f"{ports:<{W_PORTS}}"
    )

def startSniffing(iface,pack_count,output):
    packets = sniff(
        count=pack_count,
        iface=iface,
        store=True,
        prn=packetAnalysis
    )
    wrpcap(f"{output}.pcap", packets)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count",type=int,default=10)
    parser.add_argument("--iface",type=str,default="Wi-Fi")
    parser.add_argument("--output",type=str,default="network")
    args = parser.parse_args()
    print(datetime.now().time())
    print("================================================")
    print("Starting sniffer")
    print("================================================\n")
    print("-----------------Sniffer Settings---------------")
    print(f"Interface: {args.iface}")
    print(f"Count: {args.count}")
    print(f"Output: {args.output}")
    print("------------------------------------------------\n")
    
    HDR = (
        f"{'TIME':<{W_TIME}}"
        f"{'PROTO':<{W_PROTO}}"
        f"{'SRC_IP':<{W_IP}}"
        f"{'DST_IP':<{W_IP}}"
        f"{'PORTS':<{W_PORTS}}"
    )
    SEP = "─" * len(HDR)
    print(SEP)
    print(HDR)
    print(SEP)

    startSniffing(args.iface,args.count,args.output)
    print(SEP)
    print("Sniffer stopped.")
