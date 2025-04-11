#!/usr/bin/env python3
"""
IkeProbe is an IKE Service Detector, a specialized tool to detect IKE VPN services using multiple methods
Author: Vahe Demirkhanyan

This tool attempts to detect an IKE VPN service using multiple methods
and provides detailed information about the detection process.

Usage:
    python3 ikeprobe.py <target_ip> [OPTIONS]
"""

import sys
import os
import socket
import struct
import random
import time
import binascii
import argparse
import ipaddress
from scapy.all import conf, sr1, send, IP, UDP, Raw

conf.verb = 0

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

DEFAULT_PORT = 500
TIMEOUT = 3

def print_banner():
    banner = f"""
{Colors.BLUE}{Colors.BOLD}╔═══════════════════════════════════════════════╗
║                                               ║
║  IKEProbe - IKE Service Detector              ║
║  Advanced Multi-Method IKE Detection Tool     ║
║  Version: 1.0.0                               ║
║                                               ║
╚═══════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)

def parse_arguments():
    parser = argparse.ArgumentParser(description='IKE Service Detector - Multi-Method IKE Detection Tool')
    parser.add_argument('target', help='Target IP address to scan')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help=f'UDP port to scan (default: {DEFAULT_PORT})')
    parser.add_argument('-t', '--timeout', type=int, default=TIMEOUT, help=f'Timeout in seconds (default: {TIMEOUT})')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable more verbose output')
    parser.add_argument('-d', '--dump', action='store_true', help='Dump packet data in hex')
    parser.add_argument('-a', '--all', action='store_true', help='Continue testing all methods even after detection')
    return parser.parse_args()

def hexdump(data, length=16):
    result = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hexa = ' '.join([f'{b:02x}' for b in chunk])
        text = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
        result.append(f"{i:04x}  {hexa:<{length*3}}  {text}")
    return '\n'.join(result)

def send_and_receive(packet, timeout):
    try:
        response = sr1(packet, timeout=timeout, verbose=0)
        return response
    except Exception as e:
        print(f"{Colors.RED}[-] Error sending packet: {e}{Colors.ENDC}")
        return None

def method1_simple_udp(target, port, timeout, verbose, dump):
    print(f"{Colors.BLUE}[*] Method 1: Testing with simple UDP packet to port {port}{Colors.ENDC}")
    packet = IP(dst=target)/UDP(sport=random.randint(1024, 65535), dport=port)
    if verbose:
        print(f"  [*] Sending simple UDP packet")
    response = send_and_receive(packet, timeout)
    if response is None:
        print(f"  {Colors.YELLOW}[-] No response received (timeout){Colors.ENDC}")
        return False
    if UDP in response:
        print(f"  {Colors.GREEN}[+] Received UDP response{Colors.ENDC}")
        if dump:
            print(f"  {Colors.BLUE}[*] Response dump:{Colors.ENDC}")
            response.show()
        if Raw in response:
            payload = bytes(response[Raw])
            print(f"  {Colors.GREEN}[+] Response contains data ({len(payload)} bytes){Colors.ENDC}")
            if dump:
                print(f"\n{hexdump(payload)}\n")
            if len(payload) >= 1 and payload[0:1] == b'\x01':
                print(f"  {Colors.GREEN}[+] Response contains potential IKE header (starts with 0x01){Colors.ENDC}")
                return True
        return False
    else:
        print(f"  {Colors.YELLOW}[-] No UDP response{Colors.ENDC}")
        return False

def method2_ike_header(target, port, timeout, verbose, dump):
    print(f"{Colors.BLUE}[*] Method 2: Testing with basic IKE v1 header{Colors.ENDC}")
    init_cookie = random.randbytes(8)
    ike_header = (
        b'\x01\x10' +
        b'\x02' +
        b'\x00' +
        b'\x00\x00\x00\x00' +
        init_cookie +
        b'\x00' * 8
    )
    packet = IP(dst=target)/UDP(sport=random.randint(1024, 65535), dport=port)/Raw(load=ike_header)
    if verbose:
        print(f"  [*] Sending basic IKE header")
        if dump:
            print(f"  {Colors.BLUE}[*] IKE header dump:{Colors.ENDC}")
            print(f"\n{hexdump(ike_header)}\n")
    response = send_and_receive(packet, timeout)
    if response is None:
        print(f"  {Colors.YELLOW}[-] No response received (timeout){Colors.ENDC}")
        return False
    if UDP in response and Raw in response:
        payload = bytes(response[Raw])
        print(f"  {Colors.GREEN}[+] Received UDP response with data ({len(payload)} bytes){Colors.ENDC}")
        if dump:
            print(f"  {Colors.BLUE}[*] Response dump:{Colors.ENDC}")
            print(f"\n{hexdump(payload)}\n")
        if len(payload) >= 8:
            if payload[0:1] == b'\x01':
                print(f"  {Colors.GREEN}[+] Response contains IKE version 1 header{Colors.ENDC}")
                resp_init_cookie = payload[8:16]
                if resp_init_cookie == init_cookie:
                    print(f"  {Colors.GREEN}[+] Response contains matching initiator cookie{Colors.ENDC}")
                resp_cookie = payload[16:24]
                if resp_cookie != b'\x00' * 8:
                    print(f"  {Colors.GREEN}[+] Response contains non-zero responder cookie{Colors.ENDC}")
                    print(f"  {Colors.GREEN}[+] IKE SERVICE DETECTED!{Colors.ENDC}")
                    return True
        if b'INVALID-PAYLOAD-TYPE' in payload or b'INVALID-COOKIE' in payload:
            print(f"  {Colors.GREEN}[+] Response contains IKE error notification{Colors.ENDC}")
            print(f"  {Colors.GREEN}[+] IKE SERVICE DETECTED!{Colors.ENDC}")
            return True
        print(f"  {Colors.YELLOW}[-] Response doesn't appear to be a valid IKE response{Colors.ENDC}")
        return False
    else:
        print(f"  {Colors.YELLOW}[-] No data in response{Colors.ENDC}")
        return False

def method3_aggressive_mode(target, port, timeout, verbose, dump):
    print(f"{Colors.BLUE}[*] Method 3: Testing with IKE v1 Aggressive Mode packet{Colors.ENDC}")
    init_cookie = random.randbytes(8)
    ike_header = (
        b'\x01\x10' +
        b'\x03' +
        b'\x00' +
        b'\x00\x00\x00\x00' +
        init_cookie +
        b'\x00' * 8
    )
    sa_payload = (
        b'\x04' +
        b'\x00' +
        b'\x00\x24' +
        b'\x00\x00\x00\x01' +
        b'\x00\x00\x00\x01' +
        b'\x00' +
        b'\x00' +
        b'\x00' +
        b'\x01' +
        b'\x00' +
        b'\x00' +
        b'\x00\x14' +
        b'\x80\x01\x00\x05' +
        b'\x80\x02\x00\x02' +
        b'\x80\x03\x00\x01' +
        b'\x80\x04\x00\x02' +
        b'\x80\x0b\x00\x01'
    )
    ke_data = random.randbytes(128)
    ke_payload = (
        b'\x05' +
        b'\x00' +
        b'\x00\x84' +
        ke_data
    )
    nonce_data = random.randbytes(16)
    nonce_payload = (
        b'\x05' +
        b'\x00' +
        b'\x00\x14' +
        nonce_data
    )
    id_data = b'testgroup'
    id_payload = (
        b'\x00' +
        b'\x00' +
        b'\x00\x11' +
        b'\x02' +
        b'\x00\x00\x00' +
        id_data
    )
    aggressive_packet = ike_header + sa_payload + ke_payload + nonce_payload + id_payload
    packet = IP(dst=target)/UDP(sport=random.randint(1024, 65535), dport=port)/Raw(load=aggressive_packet)
    if verbose:
        print(f"  [*] Sending IKE Aggressive Mode packet")
        if dump:
            print(f"  {Colors.BLUE}[*] Packet dump:{Colors.ENDC}")
            print(f"\n{hexdump(aggressive_packet)}\n")
    response = send_and_receive(packet, timeout)
    if response is None:
        print(f"  {Colors.YELLOW}[-] No response received (timeout){Colors.ENDC}")
        return False
    if UDP in response and Raw in response:
        payload = bytes(response[Raw])
        print(f"  {Colors.GREEN}[+] Received UDP response with data ({len(payload)} bytes){Colors.ENDC}")
        if dump:
            print(f"  {Colors.BLUE}[*] Response dump:{Colors.ENDC}")
            print(f"\n{hexdump(payload)}\n")
        if len(payload) >= 8:
            if payload[0:1] == b'\x01' and payload[17:18] == b'\x03':
                print(f"  {Colors.GREEN}[+] Response contains IKE Aggressive Mode header{Colors.ENDC}")
                resp_cookie = payload[16:24]
                if resp_cookie != b'\x00' * 8:
                    print(f"  {Colors.GREEN}[+] Response contains non-zero responder cookie{Colors.ENDC}")
                    print(f"  {Colors.GREEN}[+] IKE SERVICE DETECTED WITH AGGRESSIVE MODE SUPPORT!{Colors.ENDC}")
                    return True
        if b'INVALID-PAYLOAD-TYPE' in payload or b'NO-PROPOSAL-CHOSEN' in payload:
            print(f"  {Colors.GREEN}[+] Response contains IKE error notification{Colors.ENDC}")
            print(f"  {Colors.GREEN}[+] IKE SERVICE DETECTED!{Colors.ENDC}")
            return True
        print(f"  {Colors.YELLOW}[-] Response doesn't appear to be a valid IKE Aggressive Mode response{Colors.ENDC}")
        return False
    else:
        print(f"  {Colors.YELLOW}[-] No data in response{Colors.ENDC}")
        return False

def method4_main_mode(target, port, timeout, verbose, dump):
    print(f"{Colors.BLUE}[*] Method 4: Testing with IKE v1 Main Mode packet{Colors.ENDC}")
    init_cookie = random.randbytes(8)
    ike_header = (
        b'\x01\x10' +
        b'\x02' +
        b'\x00' +
        b'\x00\x00\x00\x00' +
        init_cookie +
        b'\x00' * 8
    )
    sa_payload = (
        b'\x00' +
        b'\x00' +
        b'\x00\x24' +
        b'\x00\x00\x00\x01' +
        b'\x00\x00\x00\x01' +
        b'\x00' +
        b'\x00' +
        b'\x00' +
        b'\x01' +
        b'\x00' +
        b'\x00' +
        b'\x00\x14' +
        b'\x80\x01\x00\x05' +
        b'\x80\x02\x00\x02' +
        b'\x80\x03\x00\x01' +
        b'\x80\x04\x00\x02' +
        b'\x80\x0b\x00\x01'
    )
    main_mode_packet = ike_header + sa_payload
    packet = IP(dst=target)/UDP(sport=random.randint(1024, 65535), dport=port)/Raw(load=main_mode_packet)
    if verbose:
        print(f"  [*] Sending IKE Main Mode packet")
        if dump:
            print(f"  {Colors.BLUE}[*] Packet dump:{Colors.ENDC}")
            print(f"\n{hexdump(main_mode_packet)}\n")
    response = send_and_receive(packet, timeout)
    if response is None:
        print(f"  {Colors.YELLOW}[-] No response received (timeout){Colors.ENDC}")
        return False
    if UDP in response and Raw in response:
        payload = bytes(response[Raw])
        print(f"  {Colors.GREEN}[+] Received UDP response with data ({len(payload)} bytes){Colors.ENDC}")
        if dump:
            print(f"  {Colors.BLUE}[*] Response dump:{Colors.ENDC}")
            print(f"\n{hexdump(payload)}\n")
        if len(payload) >= 8:
            if payload[0:1] == b'\x01' and payload[17:18] == b'\x02':
                print(f"  {Colors.GREEN}[+] Response contains IKE Main Mode header{Colors.ENDC}")
                resp_cookie = payload[16:24]
                if resp_cookie != b'\x00' * 8:
                    print(f"  {Colors.GREEN}[+] Response contains non-zero responder cookie{Colors.ENDC}")
                    print(f"  {Colors.GREEN}[+] IKE SERVICE DETECTED WITH MAIN MODE SUPPORT!{Colors.ENDC}")
                    return True
        if b'INVALID-PAYLOAD-TYPE' in payload or b'NO-PROPOSAL-CHOSEN' in payload:
            print(f"  {Colors.GREEN}[+] Response contains IKE error notification{Colors.ENDC}")
            print(f"  {Colors.GREEN}[+] IKE SERVICE DETECTED!{Colors.ENDC}")
            return True
        print(f"  {Colors.YELLOW}[-] Response doesn't appear to be a valid IKE Main Mode response{Colors.ENDC}")
        return False
    else:
        print(f"  {Colors.YELLOW}[-] No data in response{Colors.ENDC}")
        return False

def method5_ikev2(target, port, timeout, verbose, dump):
    print(f"{Colors.BLUE}[*] Method 5: Testing with IKEv2 packet{Colors.ENDC}")
    init_spi = random.randbytes(8)
    ikev2_header = (
        b'\x02' +
        b'\x00' +
        b'\x22' +
        b'\x08' +
        b'\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00' +
        init_spi +
        b'\x00' * 8
    )
    sa_payload = (
        b'\x22' +
        b'\x00' +
        b'\x00\x24' +
        b'\x01' +
        b'\x00' +
        b'\x00' +
        b'\x03' +
        b'\x00\x01\x00\x0c' +
        b'\x00\x02\x00\x05' +
        b'\x00\x03\x00\x08'
    )
    ke_data = random.randbytes(64)
    ke_payload = (
        b'\x28' +
        b'\x00' +
        b'\x00\x88' +
        b'\x00\x02' +
        b'\x00\x00' +
        ke_data
    )
    nonce_data = random.randbytes(16)
    nonce_payload = (
        b'\x00' +
        b'\x00' +
        b'\x00\x14' +
        nonce_data
    )
    ikev2_packet = ikev2_header + sa_payload + ke_payload + nonce_payload
    total_length = len(ikev2_packet)
    ikev2_packet = ikev2_packet[:12] + struct.pack("!I", total_length - 4) + ikev2_packet[16:]
    packet = IP(dst=target)/UDP(sport=random.randint(1024, 65535), dport=port)/Raw(load=ikev2_packet)
    if verbose:
        print(f"  [*] Sending IKEv2 packet")
        if dump:
            print(f"  {Colors.BLUE}[*] Packet dump:{Colors.ENDC}")
            print(f"\n{hexdump(ikev2_packet)}\n")
    response = send_and_receive(packet, timeout)
    if response is None:
        print(f"  {Colors.YELLOW}[-] No response received (timeout){Colors.ENDC}")
        return False
    if UDP in response and Raw in response:
        payload = bytes(response[Raw])
        print(f"  {Colors.GREEN}[+] Received UDP response with data ({len(payload)} bytes){Colors.ENDC}")
        if dump:
            print(f"  {Colors.BLUE}[*] Response dump:{Colors.ENDC}")
            print(f"\n{hexdump(payload)}\n")
        if len(payload) >= 8:
            if payload[0:1] == b'\x02':
                print(f"  {Colors.GREEN}[+] Response contains IKEv2 header{Colors.ENDC}")
                print(f"  {Colors.GREEN}[+] IKEv2 SERVICE DETECTED!{Colors.ENDC}")
                return True
        if b'INVALID-PAYLOAD-TYPE' in payload or b'INVALID-MAJOR-VERSION' in payload:
            print(f"  {Colors.GREEN}[+] Response contains IKE error notification{Colors.ENDC}")
            print(f"  {Colors.GREEN}[+] IKE SERVICE DETECTED!{Colors.ENDC}")
            return True
        print(f"  {Colors.YELLOW}[-] Response doesn't appear to be a valid IKEv2 response{Colors.ENDC}")
        return False
    else:
        print(f"  {Colors.YELLOW}[-] No data in response{Colors.ENDC}")
        return False

def main():
    print_banner()
    args = parse_arguments()
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        print(f"{Colors.RED}[-] Invalid IP address: {args.target}{Colors.ENDC}")
        return 1
    print(f"{Colors.BLUE}[*] Target: {args.target}:{args.port}{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Timeout: {args.timeout} seconds{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Testing IKE service using multiple methods...{Colors.ENDC}\n")
    methods = [
        method1_simple_udp,
        method2_ike_header,
        method3_aggressive_mode,
        method4_main_mode,
        method5_ikev2
    ]
    successful_methods = []
    for i, method in enumerate(methods):
        detected = method(args.target, args.port, args.timeout, args.verbose, args.dump)
        if detected:
            successful_methods.append(i+1)
            if not args.all:
                break
        print("")
    print(f"{Colors.BLUE}{Colors.BOLD}======== DETECTION SUMMARY ========{Colors.ENDC}")
    if successful_methods:
        print(f"{Colors.GREEN}[+] IKE service detected on {args.target}:{args.port}{Colors.ENDC}")
        print(f"{Colors.GREEN}[+] Successful detection methods: {', '.join(map(str, successful_methods))}{Colors.ENDC}")
    else:
        print(f"{Colors.RED}[-] No IKE service detected on {args.target}:{args.port}{Colors.ENDC}")
        print(f"{Colors.YELLOW}[!] Possible reasons:{Colors.ENDC}")
        print(f"{Colors.YELLOW}    - No IKE service is running{Colors.ENDC}")
        print(f"{Colors.YELLOW}    - The service is on a different port{Colors.ENDC}")
        print(f"{Colors.YELLOW}    - Firewall is blocking UDP traffic{Colors.ENDC}")
        print(f"{Colors.YELLOW}    - The service requires specific parameters not used in these tests{Colors.ENDC}")
    print(f"{Colors.BLUE}{Colors.BOLD}================================{Colors.ENDC}")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[-] Error: {e}{Colors.ENDC}")
        sys.exit(1)
