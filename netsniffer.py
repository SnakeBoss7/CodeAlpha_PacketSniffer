#!/usr/bin/env python3
"""
NetSniffer - Network Packet Analyzer
A Wireshark-lite tool for capturing and analyzing network traffic.
Built for cybersecurity fundamentals learning.
"""

import sys
import signal
import argparse
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        Raw, Ether, ARP, wrpcap, get_if_list
    )

except ImportError:
    print("[!] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

# ─────────────────────────── ANSI Colors ────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"

# ─────────────────────────── Stats Tracker ──────────────────────────
class Stats:
    def __init__(self):
        self.total       = 0
        self.protocols   = defaultdict(int)
        self.top_src_ips = defaultdict(int)
        self.top_dst_ips = defaultdict(int)
        self.dns_queries = []
        self.captured    = []          # for pcap saving

stats = Stats()

# ─────────────────────────── Helpers ────────────────────────────────
def proto_color(proto: str) -> str:
    colors = {
        "TCP":   C.GREEN,
        "UDP":   C.CYAN,
        "ICMP":  C.YELLOW,
        "DNS":   C.MAGENTA,
        "HTTP":  C.BLUE,
        "ARP":   C.WHITE,
        "OTHER": C.DIM,
    }
    return colors.get(proto, C.DIM)

def fmt_payload(raw_bytes: bytes, max_len: int = 80) -> str:
    """Show printable payload chars, truncate if long."""
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        text = "".join(c if c.isprintable() else "." for c in text)
        return (text[:max_len] + "…") if len(text) > max_len else text
    except Exception:
        return repr(raw_bytes[:max_len])

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ███╗   ██╗███████╗████████╗███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
  ██║ ╚████║███████╗   ██║   ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{C.RESET}  {C.DIM}Python Network Packet Analyzer | Press Ctrl+C to stop and view summary{C.RESET}
""")

# ─────────────────────────── Core Packet Handler ────────────────────
def process_packet(pkt):
    stats.total += 1
    stats.captured.append(pkt)

    ts      = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto   = "OTHER"
    src_ip  = dst_ip = src_port = dst_port = flags = payload_str = ""
    extra   = ""

    # ── Layer 2: ARP ──────────────────────────────────────────────
    if ARP in pkt:
        proto   = "ARP"
        op      = "REQUEST" if pkt[ARP].op == 1 else "REPLY"
        src_ip  = pkt[ARP].psrc
        dst_ip  = pkt[ARP].pdst
        extra   = f"[{op}] {pkt[ARP].hwsrc} → {pkt[ARP].hwdst}"

    # ── Layer 3+: IP-based ────────────────────────────────────────
    elif IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        stats.top_src_ips[src_ip] += 1
        stats.top_dst_ips[dst_ip] += 1

        # ── TCP ──────────────────────────────────────────────────
        if TCP in pkt:
            proto    = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            raw_flags = pkt[TCP].flags

            # Decode TCP flags
            flag_map = {0x01:"FIN",0x02:"SYN",0x04:"RST",0x08:"PSH",
                        0x10:"ACK",0x20:"URG",0x40:"ECE",0x80:"CWR"}
            flags = "+".join(v for k,v in flag_map.items() if int(raw_flags) & k)

            # Detect HTTP (ports 80/8080)
            if dst_port in (80, 8080) or src_port in (80, 8080):
                proto = "HTTP"

            if Raw in pkt:
                payload_str = fmt_payload(bytes(pkt[Raw]))

        # ── UDP ──────────────────────────────────────────────────
        elif UDP in pkt:
            proto    = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            # ── DNS ──────────────────────────────────────────────
            if DNS in pkt:
                proto = "DNS"
                if pkt[DNS].qr == 0 and DNSQR in pkt:   # Query
                    qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                    extra = f"{C.MAGENTA}QUERY{C.RESET}  → {qname}"
                    stats.dns_queries.append(qname)
                elif pkt[DNS].qr == 1 and DNSRR in pkt:  # Response
                    rname = pkt[DNSRR].rrname.decode(errors="replace").rstrip(".")
                    rdata = getattr(pkt[DNSRR], "rdata", "?")
                    extra = f"{C.GREEN}ANSWER{C.RESET} ← {rname} → {rdata}"
            elif Raw in pkt:
                payload_str = fmt_payload(bytes(pkt[Raw]))

        # ── ICMP ─────────────────────────────────────────────────
        elif ICMP in pkt:
            proto = "ICMP"
            icmp_types = {0:"Echo Reply", 3:"Dest Unreachable",
                          8:"Echo Request", 11:"TTL Exceeded"}
            extra = icmp_types.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")

    else:
        return  # Non-IP, non-ARP: skip

    stats.protocols[proto] += 1
    color = proto_color(proto)

    # ── Build port string ─────────────────────────────────────────
    port_str = f":{src_port} → :{dst_port}" if src_port else ""

    # ── Print line ────────────────────────────────────────────────
    print(
        f"{C.DIM}{ts}{C.RESET}  "
        f"{color}{C.BOLD}{proto:<6}{C.RESET}  "
        f"{C.WHITE}{src_ip:<15}{C.RESET} → "
        f"{C.WHITE}{dst_ip:<15}{C.RESET} "
        f"{C.DIM}{port_str:<22}{C.RESET}"
        + (f"  [{flags}]" if flags else "")
        + (f"  {extra}" if extra else "")
    )

    # ── Payload sub-line ─────────────────────────────────────────
    if payload_str:
        print(f"  {C.DIM}└─ Payload: {payload_str}{C.RESET}")

# ─────────────────────────── Summary Report ─────────────────────────
def print_summary(save_path: str = None):
    print(f"\n\n{C.CYAN}{C.BOLD}{'═'*60}")
    print(f"  SESSION SUMMARY")
    print(f"{'═'*60}{C.RESET}")

    print(f"\n  {C.BOLD}Total Packets Captured:{C.RESET} {stats.total}")

    print(f"\n  {C.BOLD}Protocol Breakdown:{C.RESET}")
    for proto, count in sorted(stats.protocols.items(), key=lambda x: -x[1]):
        bar   = "█" * min(count, 30)
        pct   = (count / stats.total * 100) if stats.total else 0
        color = proto_color(proto)
        print(f"    {color}{proto:<8}{C.RESET}  {bar:<30} {count:>5}  ({pct:.1f}%)")

    if stats.top_src_ips:
        print(f"\n  {C.BOLD}Top Source IPs:{C.RESET}")
        for ip, count in sorted(stats.top_src_ips.items(), key=lambda x: -x[1])[:5]:
            print(f"    {C.WHITE}{ip:<18}{C.RESET} {count} packets")

    if stats.top_dst_ips:
        print(f"\n  {C.BOLD}Top Destination IPs:{C.RESET}")
        for ip, count in sorted(stats.top_dst_ips.items(), key=lambda x: -x[1])[:5]:
            print(f"    {C.WHITE}{ip:<18}{C.RESET} {count} packets")

    if stats.dns_queries:
        unique_dns = list(dict.fromkeys(stats.dns_queries))[:10]
        print(f"\n  {C.BOLD}DNS Queries Seen:{C.RESET}")
        for q in unique_dns:
            print(f"    {C.MAGENTA}↳{C.RESET} {q}")

    if save_path and stats.captured:
        try:
            wrpcap(save_path, stats.captured)
            print(f"\n  {C.GREEN}✔ Saved {len(stats.captured)} packets → {save_path}{C.RESET}")
            print(f"  {C.DIM}  Open with: wireshark {save_path}{C.RESET}")
        except Exception as e:
            print(f"\n  {C.RED}✘ Could not save pcap: {e}{C.RESET}")

    print(f"\n{C.CYAN}{C.BOLD}{'═'*60}{C.RESET}\n")

# ─────────────────────────── Entry Point ────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="NetSniffer — Python Network Packet Analyzer"
    )
    parser.add_argument("-i", "--iface",   default=None,
        help="Network interface (e.g. eth0, wlan0). Default: auto-detect")
    parser.add_argument("-f", "--filter",  default=None,
        help="BPF filter string (e.g. 'tcp port 80', 'udp', 'icmp')")
    parser.add_argument("-c", "--count",   type=int, default=0,
        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-o", "--output",  default=None,
        help="Save captured packets to .pcap file (e.g. capture.pcap)")
    parser.add_argument("--list-ifaces",   action="store_true",
        help="List available network interfaces and exit")
    args = parser.parse_args()

    if args.list_ifaces:
        print(f"\n{C.BOLD}Available Interfaces:{C.RESET}")
        for iface in get_if_list():
            print(f"  {C.CYAN}•{C.RESET} {iface}")
        print()
        sys.exit(0)

    banner()

    # ── Print config ─────────────────────────────────────────────
    print(f"  {C.BOLD}Interface :{C.RESET} {args.iface or 'auto'}")
    print(f"  {C.BOLD}Filter    :{C.RESET} {args.filter or 'none (capture all)'}")
    print(f"  {C.BOLD}Count     :{C.RESET} {args.count or 'unlimited'}")
    print(f"  {C.BOLD}Save to   :{C.RESET} {args.output or 'not saving'}")
    print(f"\n  {C.DIM}{'─'*85}")
    print(f"  {'TIME':12} {'PROTO':<6}  {'SRC IP':<15}   {'DST IP':<15} {'PORTS':<22}  INFO")
    print(f"  {'─'*85}{C.RESET}\n")

    # ── Graceful Ctrl+C ───────────────────────────────────────────
    def on_exit(sig, frame):
        print_summary(args.output)
        sys.exit(0)
    signal.signal(signal.SIGINT, on_exit)

    # ── Start sniffing ────────────────────────────────────────────
    try:
        sniff(
            iface   = args.iface,
            filter  = args.filter,
            prn     = process_packet,
            count   = args.count,
            store   = False,       # don't store in scapy's memory; we track manually
        )
        # If count was set and reached, print summary normally
        print_summary(args.output)

    except PermissionError:
        print(f"\n{C.RED}[!] Permission denied — run with sudo:{C.RESET}")
        print(f"    sudo python3 packet_analyzer.py\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{C.RED}[!] Error: {e}{C.RESET}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()