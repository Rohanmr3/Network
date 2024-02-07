import argparse
import ipaddress
import socket
from scapy.all import *

VERSION = "1.0"

def is_valid_ipv4_address(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def is_valid_netmask(netmask):
    netmask = netmask[1:]
    try:
        netmask = int(netmask)
        return 1 <= netmask <= 32
    except ValueError:
        return False

def is_valid_timeout(timeout):
    try:
        timeout = float(timeout)
        return 0 < timeout <= 10
    except ValueError:
        return False

def scan_hosts(network, netmask, timeout, verbose):
    netmask = netmask[1:]
    network_cidr = f"{network}/{netmask}"
    ip_network = ipaddress.IPv4Network(network_cidr, strict=False)
    ip_list = [str(ip) for ip in ip_network.hosts()]
    num_hosts = len(ip_list)
    print("----------------------------------------------Host Scanner-----------------------------------------------")
    print(f"Network to be tested: {network_cidr}")
    print(f"Number of IP addresses to be tested: {num_hosts}")
    print(f"Timeout period: {timeout}")
    print(f"Verbose: {'Yes' if verbose else 'No'}")
    print("----------------------------------------------Start Ping Sweep-----------------------------------------------")
    responding_hosts = []
    non_responding_hosts = []
    forbidden_hosts = []


    for ip in ip_list:
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)

        if response:
            if response.haslayer(ICMP):
                if response[ICMP].type == 0:
                    print(f"{ip} is responding (Active host).")
                    responding_hosts.append(ip)
                elif response[ICMP].type == 3 and response[ICMP].code in [1, 2, 3, 9, 10, 13]:
                    if verbose:
                        print(f"{ip} is administratively forbidden")
                    forbidden_hosts.append(ip)
                else:
                    if verbose:
                        print(f"{ip} is not responding")
                    non_responding_hosts.append(ip)
            else:
                if verbose:
                    print(f"{ip} is not responding")
                non_responding_hosts.append(ip)
        else:
            if verbose:
                print(f"{ip} is not responding")
            non_responding_hosts.append(ip)

    print("----------------------------------------------Test Summary-----------------------------------------------")
    print(f"Number of Active hosts: {len(responding_hosts)}")
    print(f"Number of Non-responding hosts: {len(non_responding_hosts)}")
    print(f"Number of Administratively Forbidden hosts: {len(forbidden_hosts)}")
    print(f"Total Number of hosts Tested: {num_hosts}")

def main():
    parser = argparse.ArgumentParser(description="ICMP Host Scanner")
    parser.add_argument("--network", required=False, default="127.0.0.0", help="Subnetwork address to be scanned")
    parser.add_argument("--netmask", required=False, default="/28", help="Network mask to be used")
    parser.add_argument("--timeout", required=False, default="1", help="Timeout period waiting for a host to respond")
    parser.add_argument("--verbose", action="store_true", help="Verbose output (Print all hosts, not just active/responding hosts")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}", help="Show the version number and exit")

    args = parser.parse_args()

    if not is_valid_ipv4_address(args.network):
        print("Invalid IPv4 address for network.")
        return

    if not is_valid_netmask(args.netmask):
        print("Invalid netmask.")
        return

    if not is_valid_timeout(args.timeout):
        print("Invalid timeout value.")
        return

    scan_hosts(args.network, args.netmask, float(args.timeout), args.verbose)

if __name__ == "__main__":
    main()
