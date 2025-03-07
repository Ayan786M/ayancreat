#!/usr/bin/env python3

import argparse

def ip_to_decimal(ip):
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def decimal_to_ip(decimal):
    return f"{(decimal >> 24) & 255}.{(decimal >> 16) & 255}.{(decimal >> 8) & 255}.{decimal & 255}"

def generate_ips(start_ip, end_ip):
    start_decimal = ip_to_decimal(start_ip)
    end_decimal = ip_to_decimal(end_ip)
    
    ip_list = []
    for decimal_ip in range(start_decimal, end_decimal + 1):
        ip_list.append(decimal_to_ip(decimal_ip))
    return ip_list

def save_ips_to_file(ip_list, file_path):
    with open(file_path, 'w') as file:
        for ip in ip_list:
            file.write(ip + "\n")

def main():
    parser = argparse.ArgumentParser(description="Generate IP addresses within a range.")
    parser.add_argument("start_ip", help="Start IP address of the range.")
    parser.add_argument("end_ip", help="End IP address of the range.")
    parser.add_argument("-o", "--output", help="Output file to save the IP addresses. If not provided, IP addresses will be displayed.", default=None)
    
    args = parser.parse_args()
    
    ip_list = generate_ips(args.start_ip, args.end_ip)
    
    if args.output:
        save_ips_to_file(ip_list, args.output)
        print(f"{len(ip_list)} IP addresses generated and saved to {args.output}")
    else:
        print(f"{len(ip_list)} IP addresses generated:")
        for ip in ip_list:
            print(ip)

if __name__ == "__main__":
    main()
