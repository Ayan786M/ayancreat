#!/usr/bin/env python3
import socket
import time
from urllib.parse import urlparse
import argparse
import os
import sys

def is_ip(address):
    """Check if the address is an IP address."""
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False

def resolve_hostname(hostname, show_host=False):
    """Resolve a single hostname to an IP address."""
    try:
        parsed_hostname = urlparse(hostname).hostname if "://" in hostname else hostname
        if not parsed_hostname:
            parsed_hostname = hostname
        ip_address = socket.gethostbyname(parsed_hostname)
        if show_host:
            return f"{hostname} -> {ip_address}"
        return ip_address
    except socket.gaierror:
        if show_host:
            return f"{hostname} -> Unable to resolve"
        return "Unable to resolve"

def resolve_from_file(input_file, show_host=False):
    """Resolve hostnames from a file."""
    if not os.path.isfile(input_file):
        print(f"Error: File '{input_file}' does not exist.")
        sys.exit(1)

    ips = []
    with open(input_file, "r") as infile:
        for line in infile:
            address = line.strip()
            if address:
                if is_ip(address):
                    ips.append(address)
                else:
                    result = resolve_hostname(address, show_host=show_host)
                    ips.append(result.split(" -> ")[-1])
                    print(result)
    return ips

def resolve_from_stdin(show_host=False):
    """Resolve hostnames from standard input."""
    ips = []
    for line in sys.stdin:
        address = line.strip()
        if address:
            if is_ip(address):
                ips.append(address)
            else:
                result = resolve_hostname(address, show_host=show_host)
                ips.append(result.split(" -> ")[-1])
                print(result)
    return ips

def save_to_file(output_file, ips, show_host=False):
    """Save resolved IP addresses to a file."""
    with open(output_file, "w") as outfile:
        for ip in ips:
            if show_host:
                outfile.write(f"{ip}\n")
            else:
                outfile.write(f"{ip}\n")
    print(f"Resolved IP addresses saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Resolve hostnames to IP addresses.")
    parser.add_argument("ip_or_file", nargs='?', help="Single IP address or hostname to process.")
    parser.add_argument("-l", "--file", help="File containing hostnames or IP addresses.")
    parser.add_argument("-H", "--host", action="store_true", help="Include hostnames in the output.")
    parser.add_argument("-o", "--output", help="Output file to save the resolved IP addresses.")
    
    args = parser.parse_args()

    if not sys.stdin.isatty():
        ips = resolve_from_stdin(show_host=args.host)
    elif args.file:
        ips = resolve_from_file(args.file, show_host=args.host)
    elif args.ip_or_file:
        if is_ip(args.ip_or_file):
            ips = [args.ip_or_file]
        else:
            ips = [resolve_hostname(args.ip_or_file, show_host=args.host).split(" -> ")[-1]]
    else:
        print("Error: Either a single IP address or hostname, or a file must be provided.")
        sys.exit(1)
    
    # Output resolved IPs
    print("Resolved IP addresses:")
    for ip in ips:
        print(ip)

    # Save to file if -o is provided
    if args.output:
        save_to_file(args.output, ips, show_host=args.host)

if __name__ == "__main__":
    main()
