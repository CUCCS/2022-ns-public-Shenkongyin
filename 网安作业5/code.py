#! /usr/bin/python

from scapy.all import *
import argparse


def tcp_connect(dst_ip, dst_port, timeout):
    A = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=timeout)
    if (A is None):
        print("Filtered")
    elif (A.haslayer(TCP)):
        if (A.getlayer(TCP).flags == 0x12):  # Flags: 0x012 (SYN, ACK)
            send_rst = sr(IP(dst=dst_ip)/TCP(dport=dst_port,
                          flags="AR"), timeout=timeout)
            print("Open")
        elif (A.getlayer(TCP).flags == 0x14):  # Flags: 0x014 (RST, ACK)
            print("Closed")
    elif (A.haslayer(ICMP)):  # ICMP error packets sent by firewall
        if (int(A.getlayer(ICMP).type) == 3 and int(A.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


def tcp_stealth(dst_ip, dst_port, timeout):
   B = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=10)
    if (B is None):
        print("Filtered")
    elif (B.haslayer(TCP)):
        if (B.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip) /
                          TCP(dport=dst_port, flags="R"), timeout=10)
            print("Open")
        elif (B.getlayer(TCP).flags == 0x14):  # Flags: 0x014 (RST, ACK)
            print("Closed")
    elif (B.haslayer(ICMP)):  # ICMP error packets sent by firewall
        if (int(B.getlayer(ICMP).type) == 3 and int(B.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


def tcp_xmas(dst_ip, dst_port, timeout):
    C = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="FPU"), timeout=10)
    if (C is None):
        print("Filtered")
    elif (C.haslayer(TCP)):
        if (C.getlayer(TCP).flags == 0x14):  # Flags: 0x014 (RST, ACK)
            print("Closed")
    elif (C.haslayer(ICMP)):  # ICMP error packets sent by firewall
        if (int(C.getlayer(ICMP).type) == 3 and int(C.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


def tcp_fin(dst_ip, dst_port, timeout):
    D = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="F"), timeout=10)
    if (D is None):
        print("Filtered")
    elif (D.haslayer(TCP)):
        if (D.getlayer(TCP).flags == 0x14):  # Flags: 0x014 (RST, ACK)
            print("Closed")
    elif (D.haslayer(ICMP)):  # ICMP error packets sent by firewall
        if (int(D.getlayer(ICMP).type) == 3 and int(D.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


def tcp_null(dst_ip, dst_port, timeout):
    E = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags=""), timeout=10)
    if (E is None):
        print("Filtered")
    elif (E.haslayer(TCP)):
        if (E.getlayer(TCP).flags == 0x14):  # Flags: 0x014 (RST, ACK)
            print("Closed")
    elif (E.haslayer(ICMP)):  # ICMP error packets sent by firewall
        if (int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


def udp_scan(dst_ip, dst_port, dst_timeout):
    F = sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout)
    if (F is None):
        print("Filtered")
    elif (F.haslayer(UDP)):
        print("Open")
    elif (F.haslayer(ICMP)):  # ICMP error packets sent by firewall
        if (int(F.getlayer(ICMP).type) == 3 and int(F.getlayer(ICMP).code) == 3):
            print("Closed")
        elif (int(F.getlayer(ICMP).type) == 3 and int(F.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            print("Filtered")
        elif (F.haslayer(IP) and F.getlayer(IP).proto == IP_PROTOS.udp):
            print("Open")


parser = argparse.ArgumentParser(
    description='This is a script that scans the status of the destination port.')
parser.add_argument('-s', '--scantype', type=str, help='methods to scan the port', required=True,
                    choices=['tcp_connect', 'tcp_stealth', 'tcp_xmas', 'tcp_fin', 'tcp_null', 'udp_scan'])
parser.add_argument('-i', '--dstip', type=str,
                    help='destination IP address', required=True)
parser.add_argument('-p', '--dstport', type=int,
                    help='destination port number', required=True)
parser.add_argument('-t', '--timeout', type=int,
                    help='timeout, default=10', default=10)
args = parser.parse_args()

if __name__ == '__main__':
    try:
        print(args.scantype + " scanning...")
        if (args.scantype == 'tcp_connect'):
            tcp_connect(args.dstip, args.dstport, args.timeout)
        elif (args.scantype == 'tcp_stealth'):
            tcp_stealth(args.dstip, args.dstport, args.timeout)
        elif (args.scantype == 'tcp_xmas'):
            tcp_xmas(args.dstip, args.dstport, args.timeout)
        elif (args.scantype == 'tcp_fin'):
            tcp_fin(args.dstip, args.dstport, args.timeout)
        elif (args.scantype == 'tcp_null'):
            tcp_null(args.dstip, args.dstport, args.timeout)
        elif (args.scantype == 'udp_scan'):
            udp_scan(args.dstip, args.dstport, args.timeout)
    except Exception as e:
        print(e)