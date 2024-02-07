#!/usr/bin/env python3

import argparse
import scapy.all as scapy
import socket
import sys

def get_args():
    parser = argparse.ArgumentParser(description="Port Scanner Tool")
    parser.add_argument("--tcp", action="store_true", help="TCP port scan (mutually exclusive with --udp)")
    parser.add_argument("--udp", action="store_true", help="UDP port scan (mutually exclusive with --tdp)")
    parser.add_argument("--target", metavar="TARGET", default="127.0.0.1", help="Target IP address or hostname to scan")
    parser.add_argument("--port", metavar="PORT", default="0-80", help="Port[X] or port range [X-Y] to scan")
    parser.add_argument("--verbose", action="store_true", help="Verbose output (Print all tested ports, not just open ports)")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}", help="Show the version number and exit")
    return parser.parse_args()

VERSION = "1.0"

def is_valid_ipv4_address(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def is_valid_port(port):
    try:
        port = int(port)
        return 0 <= port <= 65535  # Port range is between 0 and 65535
    except ValueError:
        return False

def get_ip_from_hostname(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        print("Error: Invalid hostname/IP address.")
        sys.exit(1)

def scan_tcp(target, ports, verbose):
    print("TCP testing")
    print(f"Target : {target}")
    print(f"Range port to be scanned: {ports}")
    print(f"Verbose: {'Yes' if verbose else 'No'}")

    print("----------------------------------Starting TCP Port Scanning--------------------------------------")

    open_ports = []
    closed_ports = []
    filtered_ports = []

    for port in range(ports[0], ports[1] + 1):
        response, reason = scan_tcp_port(target, port)
        if response == "open":
            open_ports.append((port, reason))
            print(f"Port {port}: {response} - {reason}")

        elif response == "closed":
            closed_ports.append((port, reason))
            if verbose:
                print(f"Port {port}: {response} - {reason}")

        elif response == "filtered":
            filtered_ports.append((port, reason))
            if verbose:
                print(f"Port {port}: {response} - {reason}")

    print_summary(len(open_ports), len(closed_ports), len(filtered_ports))


def scan_tcp_port(target, port):
    scapy_socket = scapy.sr1(scapy.IP(dst=target) / scapy.TCP(dport=port, flags="S"), timeout=1, verbose=0)

    if scapy_socket and scapy_socket.haslayer(scapy.TCP):
        if scapy_socket.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
            return "open", "TCP SYN/ACK response"
        elif scapy_socket.getlayer(scapy.TCP).flags == 0x04:  # RST
            return "closed", "TCP RST response"
        else:
            return "filtered", "No response received (even after retransmissions)"
    elif scapy_socket and scapy_socket.haslayer(scapy.ICMP):
        icmp_error = scapy_socket.getlayer(scapy.ICMP)
        if icmp_error.type == 3 and icmp_error.code in [1, 2, 3, 9, 10, 13]:
            return "filtered", f"ICMP unreachable error: Type {icmp_error.type}, Code {icmp_error.code}"
    else:
        return "filtered", "No response received (even after retransmissions)"


def scan_udp(target, ports, verbose):
    print(f"\nUDP Port Scan on {target}:{ports}")
    open_ports = []
    closed_ports = []

    for port in range(ports[0], ports[1] + 1):
        response, reason = scan_udp_port(target, port)
        if response == "open":
            open_ports.append((port, reason))
            print(f"Port {port}: {response} - {reason}")
        elif response == "closed":
            closed_ports.append((port, reason))
            if verbose:
                print(f"Port {port}: {response} - {reason}")

    print_summary(len(open_ports), len(closed_ports), 0)


def scan_udp_port(target, port):
    response = None
    reason = None

    if port == 53:
        dns_query = (
                scapy.IP(dst=target) /
                scapy.UDP(dport=port) /
                scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com"))
        )
        scapy_socket = scapy.sr1(dns_query, timeout=1, verbose=0)
        if scapy_socket:
            response = "open"
            reason = "Valid response received for DNS"
        else:
            response = "closed"
            reason = "No response received for DNS"
    else:
        scapy_socket = scapy.sr1(scapy.IP(dst=target) / scapy.UDP(dport=port), timeout=1, verbose=0)
        if scapy_socket:
            response = "open"
            reason = "Valid response received"
        else:
            response = "closed"
            reason = "No response received"

    return response, reason


def print_summary(open_ports, closed_ports, filtered_ports):
    print("------------------------------------------Test Statistics-----------------------------------------")
    total_ports = open_ports + closed_ports + filtered_ports
    print(f"Total Ports Tested: {total_ports}")
    print(f"Open Ports: {open_ports}")
    print(f"Closed Ports: {closed_ports}")
    print(f"Filtered Ports: {filtered_ports}\n")

def main():
    args = get_args()

    print("---------------------------------------Port Scanner-----------------------------------------------")

    if not args.tcp and not args.udp:
        args.tcp = True

    if args.tcp and args.udp:
        print("Error: Both TCP and UDP protocols cannot be selected simultaneously.")
        sys.exit(1)

    target = args.target
    if not is_valid_ipv4_address(target):
        target = get_ip_from_hostname(target)

    if args.tcp:
        protocol = "TCP"
        ports = parse_ports_argument(args.port)
        if not all(is_valid_port(port) for port in ports):
            print("Invalid port or port range.")
            sys.exit(1)
        scan_tcp(target, ports, args.verbose)
    elif args.udp:
        protocol = "UDP"
        ports = parse_ports_argument(args.port)
        if not all(is_valid_port(port) for port in ports):
            print("Invalid port or port range.")
            sys.exit(1)
        scan_udp(target, ports, args.verbose)
    else:
        print("Error: Please specify either --tcp or --udp.")
        sys.exit(1)

def parse_ports_argument(port_arg):
    try:
        if "-" in port_arg:
            start, end = map(int, port_arg.split("-"))
            return (start, end)
        else:
            port = int(port_arg)
            return (port, port)
    except ValueError:
        print("Error: Invalid port format. Please use a valid port or port range.")
        sys.exit(1)

if __name__ == "__main__":
    main()
