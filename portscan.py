#!/usr/bin/env python3
import socket
import argparse
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor

VERSION = "1.3"

# Colors for output
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
ORANGE = "\033[33m"
ENDC = "\033[0m"

# Global variables for progress tracking
progress_lock = threading.Lock()
progress_counter = 0
total_scans = 0

def display_banner():
    banner = rf"""
{BLUE}
    ________            _______   ________                    
   /  _____/_____ ___  __\   _  \  \_____  \                   
  /   \  ___\__  \\  \/  /  /_\  \  /   |   \                  
  \    \_\  \/ __ \\   /    |    \/    |    \                 
   \______  (____  /\_/ \____|__  /\_______  /                 
          \/     \/             \/         \/                  
{ENDC}
   Comprehensive Port Scanner v{VERSION}
"""
    print(banner)

def create_socket(ip, port, timeout):
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return sock
    except Exception:
        return None

def get_port_service(port):
    """Return the common service name for a given port."""
    common_ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        465: "SMTPS",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
    }
    return common_ports.get(port, "Unknown")

def get_server_banner(sock):
    """Retrieve the server banner for the service."""
    try:
        sock.send(b"\r\n")
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner
    except Exception:
        return None
    finally:
        sock.close()

def scan_ip_port(ip, port, timeout, results):
    """Scan a specific port for a given IP."""
    sock = create_socket(ip, port, timeout)
    if sock:
        banner = get_server_banner(sock)
        if banner:  # Service detected
            with progress_lock:
                results[ip].append((port, banner))
                print(f"\n{GREEN}[+] IP: {ip} - Port: {port} ({get_port_service(port)}) is open - Service: {banner}{ENDC}")
        sock.close()

def scan_port(ips, port, timeout, results):
    """Scan a specific port across all IPs."""
    global progress_counter
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_ip_port, ip, port, timeout, results) for ip in ips]
        for future in futures:
            future.result()
            with progress_lock:
                progress_counter += 1
                print(f"\r{GREEN}Progress: {progress_counter}/{total_scans} scans completed{ENDC}", end="")

def process_ip_list(ip_list_file):
    """Process a file containing a list of IPs or CIDR ranges."""
    ips = []
    try:
        with open(ip_list_file, 'r') as file:
            for line in file:
                target = line.strip()
                if '/' in target:
                    try:
                        network = ipaddress.ip_network(target, strict=False)
                        ips.extend([str(ip) for ip in network.hosts()])
                    except ValueError:
                        print(f"{RED}[-] Invalid CIDR notation: {target}{ENDC}")
                else:
                    ips.append(target)
    except IOError:
        print(f"{RED}[-] Could not read file: {ip_list_file}{ENDC}")
    return ips

def main():
    global total_scans
    display_banner()

    parser = argparse.ArgumentParser(description="Comprehensive Port Scanner for common ports.")
    parser.add_argument(
        "targets", nargs='*', help="IP addresses, domain names, or CIDR networks to scan."
    )
    parser.add_argument(
        "-p", "--ports", type=int, nargs='+', default=[21, 22, 25, 110, 143, 465, 993, 995, 3306],
        help="Ports to scan (default: common ports)."
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1 second)."
    )
    parser.add_argument(
        "-l", "--list", help="File containing a list of IP addresses or CIDR networks."
    )
    parser.add_argument(
        "-o", "--output", help="File to save scan results."
    )

    args = parser.parse_args()
    ports = args.ports
    timeout = args.timeout

    # Process targets
    ips = set()
    if args.list:
        ips.update(process_ip_list(args.list))
    for target in args.targets:
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                ips.update([str(ip) for ip in network.hosts()])
            except ValueError:
                print(f"{RED}[-] Invalid CIDR notation: {target}{ENDC}")
        else:
            ips.add(target.strip())

    if not ips:
        print(f"{RED}[-] No valid targets specified!{ENDC}")
        return

    ips = list(ips)
    total_scans = len(ips) * len(ports)

    results = {ip: [] for ip in ips}
    for port in ports:
        print(f"\n{ORANGE}Scanning port {port} ({get_port_service(port)})...{ENDC}")
        scan_port(ips, port, timeout, results)

    # Save results to a file if specified
    if args.output:
        with open(args.output, 'w') as file:
            for ip, open_ports in results.items():
                if open_ports:
                    file.write(f"IP: {ip} - Open Ports: {', '.join(f'{port} ({get_port_service(port)}) - Service: {banner}' for port, banner in open_ports)}\n")
        print(f"{GREEN}[+] Results saved to {args.output}{ENDC}")

if __name__ == "__main__":
    main()
