#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IKEProbe — IKE Service Detector (v1 + v2), IPv4/IPv6, NAT-T aware
Author: Vahe Demirkhanyan (refactored & hardened)

Requires: scapy (and scapy.contrib.ikev2 if you want IKEv2 probing)
"""

import sys
import os
import argparse
import ipaddress
import random
import struct
from typing import Optional, Tuple

# scapy core
from scapy.all import conf, sr1, IP, IPv6, UDP, Raw
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import ICMPv6DestUnreach
from scapy.compat import raw as scapy_raw

# IKEv1 / ISAKMP
from scapy.layers.isakmp import (
    ISAKMP,
    ISAKMP_payload_SA,
    ISAKMP_payload_Proposal,
    ISAKMP_payload_Transform,
)

# IKEv2 contrib (optional)
_HAVE_IKEV2 = True
try:
    from scapy.contrib.ikev2 import (
        IKEv2, IKEv2_init,
        IKEv2_SA, IKEv2_Proposal, IKEv2_Transform,
        IKEv2_KE, IKEv2_Nonce,
        TransformType, TransformID,
    )
except Exception:
    _HAVE_IKEV2 = False

conf.verb = 0

# ---------------- Colors ----------------
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

DEFAULT_PORT = 500
TIMEOUT = 3

# Optional fixed source port for NATs
_SRC_PORT: Optional[int] = None

# ---------------- Utils ----------------
def print_banner():
    banner = f"""
{Colors.BLUE}{Colors.BOLD}╔═══════════════════════════════════════════════╗
║                                               ║
║  IKEProbe - IKE Service Detector              ║
║  IKEv1 / IKEv2 • IPv4/IPv6 • NAT-T aware      ║
║  Version: 1.4.0                               ║
║                                               ║
╚═══════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)

def hexdump(data: bytes, length: int = 16) -> str:
    out = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hexa = ' '.join(f'{b:02x}' for b in chunk)
        text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        out.append(f"{i:04x}  {hexa:<{length*3}}  {text}")
    return '\n'.join(out)

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True  # Windows: best effort

def ip_layer_for(target_ip: str):
    ipobj = ipaddress.ip_address(target_ip)
    return IPv6(dst=str(ipobj)) if ipobj.version == 6 else IP(dst=str(ipobj))

def udp_status(resp) -> str:
    if resp is None:
        return "no_reply"
    if resp.haslayer(ICMP):
        ic = resp[ICMP]
        if ic.type == 3 and ic.code == 3:
            return "closed"  # IPv4 Port Unreachable
        return "filtered"
    if resp.haslayer(ICMPv6DestUnreach):
        ic6 = resp[ICMPv6DestUnreach]
        if getattr(ic6, "code", None) == 4:
            return "closed"  # IPv6 Port Unreachable
        return "filtered"
    if resp.haslayer(UDP):
        return "udp_reply"
    if resp.haslayer(Raw):
        return "raw_reply"
    return "unknown"

def parse_isakmp_header(data: bytes) -> Optional[dict]:
    # Common 28-byte IKE/ISAKMP header
    if len(data) < 28:
        return None
    init_spi = data[0:8]
    resp_spi = data[8:16]
    next_pl, ver, exch, flags = struct.unpack("!BBBB", data[16:20])
    msg_id = struct.unpack("!I", data[20:24])[0]
    length = struct.unpack("!I", data[24:28])[0]
    return {
        "init_spi": init_spi,
        "resp_spi": resp_spi,
        "next_pl": next_pl,
        "ver": ver,   # 0x10 (v1) or 0x20 (v2)
        "exch": exch, # v1: 2 Main / 4 Aggressive ; v2: 34 IKE_SA_INIT, 35 IKE_AUTH, 37 INFORMATIONAL
        "flags": flags,
        "msg_id": msg_id,
        "length": length
    }

def send_and_receive(pkt, timeout: int):
    try:
        return sr1(pkt, timeout=timeout, verbose=0)
    except Exception as e:
        print(f"{Colors.RED}[-] Error sending packet: {e}{Colors.ENDC}")
        return None

# ---------------- IKEv1 builders ----------------
def build_ikev1_main_probe_bytes(sit: int = 1) -> bytes:
    """
    IKEv1 Main Mode: SA with two proposals (3DES & AES-128) to maximize replies.
    SPI size MUST be 0 (empty) for phase 1.
    """
    # 3DES proposal
    t3des = ISAKMP_payload_Transform(transform_type=1, transform_id=5)   # ENCR_3DES
    thash = ISAKMP_payload_Transform(transform_type=2, transform_id=2)   # HASH_SHA1
    tauth = ISAKMP_payload_Transform(transform_type=3, transform_id=1)   # AUTH_PRESHARED_KEY
    tgrp  = ISAKMP_payload_Transform(transform_type=4, transform_id=14)  # MODP_2048 (Grp 14)
    prop3 = ISAKMP_payload_Proposal(proposal=1, proto=1, spi=b"", trans_nb=4) / t3des / thash / tauth / tgrp

    # AES-128 proposal (transform_id=7)
    taes  = ISAKMP_payload_Transform(transform_type=1, transform_id=7)   # ENCR_AES_CBC
    propA = ISAKMP_payload_Proposal(proposal=2, proto=1, spi=b"", trans_nb=4) / taes / thash / tauth / tgrp

    sa = ISAKMP_payload_SA(doi=1, sit=sit) / prop3 / propA

    ike = ISAKMP(
        init_cookie=os.urandom(8),
        resp_cookie=b"\x00"*8,
        next_payload=1, version=0x10, exch_type=2, flags=0x00, id=0
    ) / sa

    return scapy_raw(ike)

def build_ikev1_aggressive_probe_bytes(sit: int = 1) -> bytes:
    """
    IKEv1 Aggressive Mode (best-effort): SA with both 3DES and AES proposals.
    Many stacks want KE+Ni+IDii here; we intentionally keep this secondary.
    """
    # 3DES
    t3des = ISAKMP_payload_Transform(transform_type=1, transform_id=5)
    thash = ISAKMP_payload_Transform(transform_type=2, transform_id=2)
    tauth = ISAKMP_payload_Transform(transform_type=3, transform_id=1)
    tgrp  = ISAKMP_payload_Transform(transform_type=4, transform_id=14)
    prop3 = ISAKMP_payload_Proposal(proposal=1, proto=1, spi=b"", trans_nb=4) / t3des / thash / tauth / tgrp

    # AES
    taes  = ISAKMP_payload_Transform(transform_type=1, transform_id=7)
    propA = ISAKMP_payload_Proposal(proposal=2, proto=1, spi=b"", trans_nb=4) / taes / thash / tauth / tgrp

    sa = ISAKMP_payload_SA(doi=1, sit=sit) / prop3 / propA

    ike = ISAKMP(
        init_cookie=os.urandom(8),
        resp_cookie=b"\x00"*8,
        next_payload=1, version=0x10, exch_type=4, flags=0x00, id=0
    ) / sa

    return scapy_raw(ike)

# ---------------- IKEv2 builder (robust + fallback) ----------------
def build_ikev2_init_probe_bytes() -> Optional[bytes]:
    """
    Build IKEv2 IKE_SA_INIT:
      - Preferred: Scapy contrib ikev2 with SA (AES-128/SHA1/PRF-HMAC-SHA1/DH14) + KE + Ni
      - Fallback: spec-correct raw header + empty SA payload header.
    """
    if not _HAVE_IKEV2:
        return None
    try:
        # Robust across scapy versions
        TT_ENCR = getattr(TransformType, 'ENCR', 1)
        TT_PRF  = getattr(TransformType, 'PRF',  2)
        TT_INTEG = getattr(TransformType, 'INTEG', getattr(TransformType, 'AUTH', 3))
        TT_DH   = getattr(TransformType, 'DH',   4)

        DH14 = getattr(TransformID, 'DH_2048', 14)
        ENCR_AES_CBC = getattr(TransformID, 'ENCR_AES_CBC', 12)
        PRF_HMAC_SHA1 = getattr(TransformID, 'PRF_HMAC_SHA1', 2)
        INTEG_HMAC_SHA1_96 = getattr(TransformID, 'AUTH_HMAC_SHA1_96', 2)

        # AES-128 key length attribute (TV: type 14 with high bit set)
        AES128_TV_ATTR = b"\x80\x0e\x00\x80"

        try:
            encr_tr = IKEv2_Transform(transform_type=TT_ENCR,
                                      transform_id=ENCR_AES_CBC,
                                      attr=AES128_TV_ATTR)
        except TypeError:
            # Some scapy builds want an int key length instead of bytes
            encr_tr = IKEv2_Transform(transform_type=TT_ENCR,
                                      transform_id=ENCR_AES_CBC,
                                      attr=16)

        prop = IKEv2_Proposal(proposal=1, proto=1, spi=b"", trans_nb=4) / (
            encr_tr /
            IKEv2_Transform(transform_type=TT_PRF,   transform_id=PRF_HMAC_SHA1) /
            IKEv2_Transform(transform_type=TT_INTEG, transform_id=INTEG_HMAC_SHA1_96) /
            IKEv2_Transform(transform_type=TT_DH,    transform_id=DH14)
        )
        sa = IKEv2_SA() / prop
        ke = IKEv2_KE(group=14, ke_data=os.urandom(256))  # MODP-2048 sized blob (good enough to trigger NOTIFY/response)
        ni = IKEv2_Nonce(nonce=os.urandom(32))

        ike = IKEv2(init_SPI=int.from_bytes(os.urandom(8), "big")) / IKEv2_init() / sa / ke / ni
        return scapy_raw(ike)
    except Exception:
        # Raw minimal fallback: header + SA header only
        init_spi = os.urandom(8); resp_spi = b"\x00"*8
        sa_pld = bytes([33, 0]) + struct.pack("!H", 4)  # type=SA(33), flags=0, length=4
        header = (init_spi + resp_spi +
                  bytes([33, 0x20, 34, 0x08]) +         # next=SA, ver=0x20, exch=34 (IKE_SA_INIT), flags=0x08 (Initiator)
                  struct.pack("!I", 0) +
                  struct.pack("!I", 28 + len(sa_pld)))
        return header + sa_pld

# ---------------- IKEv2 NOTIFY helpers (optional operator candy) ----------------
def _ikev2_iter_payloads(buf: bytes):
    """Very light walker to list payloads in an IKEv2 message (no crypt/decrypt)."""
    if len(buf) < 28:
        return
    np = buf[16]
    off = 28
    while np and off + 4 <= len(buf):
        cur = np
        if off + 4 > len(buf):
            break
        next_np = buf[off]
        length = struct.unpack("!H", buf[off+2:off+4])[0]
        if length < 4 or off + length > len(buf):
            break
        body = buf[off+4:off+length]
        yield cur, body
        np = next_np
        off += length

def _pretty_notify(code: int) -> str:
    names = {
        14: "INVALID_KE_PAYLOAD",
        24: "NO_PROPOSAL_CHOSEN",
        16388: "NAT_DETECTION_SOURCE_IP",
        16389: "NAT_DETECTION_DESTINATION_IP",
        16390: "COOKIE",
    }
    return names.get(code, f"NOTIFY({code})")

# ---------------- Send helpers ----------------
def _send_ike_bytes(target: str, port: int, payload_bytes: bytes, timeout: int, dump: bool) -> Tuple[object, str, bytes]:
    """
    Sends IKE bytes over UDP (adds/removes NAT-T non-ESP marker on 4500).
    Returns (resp, status, raw_resp_bytes_stripped)
    """
    ipL = ip_layer_for(target)
    sport = _SRC_PORT if _SRC_PORT else random.randint(1024, 65535)

    payload = (b"\x00\x00\x00\x00" + payload_bytes) if port == 4500 else payload_bytes
    pkt = ipL / UDP(sport=sport, dport=port) / Raw(load=payload)

    if dump:
        print(f"  --- Sent ({len(payload)} bytes) ---")
        print(hexdump(payload))

    resp = send_and_receive(pkt, timeout)
    st = udp_status(resp)
    raw_resp = bytes(resp[Raw]) if (resp and resp.haslayer(Raw)) else b""

    # Strip NAT-T non-ESP marker on replies from 4500
    if port == 4500 and raw_resp.startswith(b"\x00\x00\x00\x00") and len(raw_resp) >= 32:
        raw_resp = raw_resp[4:]

    if dump and raw_resp:
        print(f"  --- Recv ({len(raw_resp)} bytes) ---")
        print(hexdump(raw_resp))
    return resp, st, raw_resp

def _send_with_retries(sender, retries: int = 0):
    """Wrap a sender() -> (resp, st, raw) to retry on 'no_reply' N times."""
    def run():
        resp, st, raw = sender()
        attempts = 0
        while retries > 0 and st == "no_reply" and attempts < retries:
            resp, st, raw = sender()
            attempts += 1
        return resp, st, raw
    return run

def _post_parse_notes(port: int):
    if port == 4500:
        print(f"  {Colors.GREEN}[+] NAT-T path in use (UDP/4500).{Colors.ENDC}")

def _header_sanity_notes(hdr: Optional[dict], raw_resp_len: int):
    if hdr and hdr["length"] > raw_resp_len:
        print(f"  {Colors.YELLOW}[!] Truncated IKE message (len field {hdr['length']} > actual {raw_resp_len}).{Colors.ENDC}")

# ---------------- Methods ----------------
def method0_simple_udp(target: str, port: int, timeout: int, verbose: bool, dump: bool, retries: int) -> bool:
    print(f"{Colors.BLUE}[*] Method 0: Simple UDP poke (reachability hint){Colors.ENDC}")
    ipL = ip_layer_for(target)
    pkt = ipL / UDP(sport=random.randint(1024, 65535), dport=port)

    def sender():
        resp = send_and_receive(pkt, timeout)
        return resp, udp_status(resp), bytes(resp[Raw]) if (resp and resp.haslayer(Raw)) else b""

    resp, st, _ = _send_with_retries(sender, retries)()
    if st == "udp_reply":
        print(f"  {Colors.YELLOW}[~] UDP echoed, but not proof of IKE. Continuing…{Colors.ENDC}")
    elif st == "closed":
        print(f"  {Colors.YELLOW}[-] ICMP Port Unreachable (closed).{Colors.ENDC}")
    else:
        print(f"  {Colors.YELLOW}[-] No meaningful UDP response ({st}).{Colors.ENDC}")
    return False  # non-authoritative

def method1_ikev1_main(target: str, port: int, timeout: int, verbose: bool, dump: bool, retries: int) -> bool:
    print(f"{Colors.BLUE}[*] Method 1: IKEv1 Main Mode probe (SA: 3DES + AES){Colors.ENDC}")

    def do_probe(sit: int) -> Tuple[object, str, bytes]:
        pkt_bytes = build_ikev1_main_probe_bytes(sit=sit)
        return _send_ike_bytes(target, port, pkt_bytes, timeout, dump)

    # Primary try with sit=1
    resp, st, raw_resp = _send_with_retries(lambda: do_probe(1), retries)()
    if st == "closed":
        print(f"  {Colors.YELLOW}[-] ICMP Port Unreachable (closed).{Colors.ENDC}")
        return False
    if not raw_resp:
        # Retry once with sit=0 (some stacks prefer it)
        resp, st, raw_resp = do_probe(0)

    if not raw_resp:
        print(f"  {Colors.YELLOW}[-] No response ({st}).{Colors.ENDC}")
        return False

    hdr = parse_isakmp_header(raw_resp)
    _header_sanity_notes(hdr, len(raw_resp))
    if hdr and hdr["ver"] == 0x10 and hdr["resp_spi"] != b"\x00"*8 and hdr["exch"] in (2, 4):
        if verbose:
            print(f"  Parsed v1 header: exch={hdr['exch']} flags=0x{hdr['flags']:02x} length={hdr['length']}")
        print(f"  {Colors.GREEN}[+] IKEv1 service detected (Main/Aggressive).{Colors.ENDC}")
        _post_parse_notes(port)
        return True

    if resp and resp.haslayer(ISAKMP):
        print(f"  {Colors.GREEN}[+] IKEv1 service detected (ISAKMP layer present).{Colors.ENDC}")
        _post_parse_notes(port)
        return True

    print(f"  {Colors.YELLOW}[-] Response didn’t look like valid IKEv1.{Colors.ENDC}")
    return False

def method2_ikev1_aggressive(target: str, port: int, timeout: int, verbose: bool, dump: bool, retries: int) -> bool:
    print(f"{Colors.BLUE}[*] Method 2: IKEv1 Aggressive Mode probe (best-effort){Colors.ENDC}")

    def do_probe(sit: int):
        pkt_bytes = build_ikev1_aggressive_probe_bytes(sit=sit)
        return _send_ike_bytes(target, port, pkt_bytes, timeout, dump)

    # try sit=1 with retries
    resp, st, raw_resp = _send_with_retries(lambda: do_probe(1), retries)()
    if st == "closed":
        print(f"  {Colors.YELLOW}[-] ICMP Port Unreachable (closed).{Colors.ENDC}")
        return False
    if not raw_resp:
        # extra shot with sit=0
        resp, st, raw_resp = do_probe(0)

    if not raw_resp:
        print(f"  {Colors.YELLOW}[-] No response ({st}).{Colors.ENDC}")
        return False

    hdr = parse_isakmp_header(raw_resp)
    _header_sanity_notes(hdr, len(raw_resp))
    if hdr and hdr["ver"] == 0x10 and hdr["resp_spi"] != b"\x00"*8 and hdr["exch"] in (2, 4):
        if verbose:
            print(f"  Parsed v1 header: exch={hdr['exch']} flags=0x{hdr['flags']:02x} length={hdr['length']}")
        print(f"  {Colors.GREEN}[+] IKEv1 service detected (Aggressive/Main).{Colors.ENDC}")
        _post_parse_notes(port)
        return True

    if resp and resp.haslayer(ISAKMP):
        print(f"  {Colors.GREEN}[+] IKEv1 service detected (ISAKMP layer present).{Colors.ENDC}")
        _post_parse_notes(port)
        return True

    print(f"  {Colors.YELLOW}[-] Response didn’t look like valid IKEv1.{Colors.ENDC}")
    return False

def method3_ikev2_init(target: str, port: int, timeout: int, verbose: bool, dump: bool, retries: int) -> bool:
    print(f"{Colors.BLUE}[*] Method 3: IKEv2 IKE_SA_INIT probe (SA+KE+Ni){Colors.ENDC}")
    if not _HAVE_IKEV2:
        print(f"  {Colors.YELLOW}[!] scapy.contrib.ikev2 not available; skipping IKEv2 probe.{Colors.ENDC}")
        return False

    pkt_bytes = build_ikev2_init_probe_bytes()
    if pkt_bytes is None:
        print(f"  {Colors.YELLOW}[!] Couldn’t build IKEv2 packet; skipping.{Colors.ENDC}")
        return False

    def sender():
        return _send_ike_bytes(target, port, pkt_bytes, timeout, dump)

    resp, st, raw_resp = _send_with_retries(sender, retries)()
    if st == "closed":
        print(f"  {Colors.YELLOW}[-] ICMP Port Unreachable (closed).{Colors.ENDC}")
        return False
    if not raw_resp:
        print(f"  {Colors.YELLOW}[-] No response ({st}).{Colors.ENDC}")
        return False

    hdr = parse_isakmp_header(raw_resp)
    _header_sanity_notes(hdr, len(raw_resp))

    # Tightened acceptance: expect IKE_SA_INIT and non-zero responder SPI
    if hdr and hdr["ver"] == 0x20 and hdr["exch"] == 34 and hdr["resp_spi"] != b"\x00"*8:
        if verbose:
            print(f"  Parsed v2 header: exch={hdr['exch']} flags=0x{hdr['flags']:02x} length={hdr['length']}")
        print(f"  {Colors.GREEN}[+] IKEv2 service detected.{Colors.ENDC}")
        _post_parse_notes(port)

        # Optional: print common NOTIFYs for operator clarity
        for ptype, body in _ikev2_iter_payloads(raw_resp):
            if ptype == 41 and len(body) >= 4:  # NOTIFY
                ncode = struct.unpack("!H", body[2:4])[0]
                print(f"  {Colors.YELLOW}[i] IKEv2 notify: {_pretty_notify(ncode)}{Colors.ENDC}")

        return True

    if resp and _HAVE_IKEV2 and resp.haslayer(IKEv2):
        print(f"  {Colors.GREEN}[+] IKEv2 service detected (IKEv2 layer present).{Colors.ENDC}")
        _post_parse_notes(port)

        # Optional: NOTIFYs
        for ptype, body in _ikev2_iter_payloads(raw_resp):
            if ptype == 41 and len(body) >= 4:
                ncode = struct.unpack("!H", body[2:4])[0]
                print(f"  {Colors.YELLOW}[i] IKEv2 notify: {_pretty_notify(ncode)}{Colors.ENDC}")

        return True

    print(f"  {Colors.YELLOW}[-] Response didn’t look like valid IKEv2.{Colors.ENDC}")
    return False

# ---------------- CLI ----------------
def parse_arguments():
    p = argparse.ArgumentParser(description='IKE Service Detector (IKEv1/IKEv2)')
    p.add_argument('target', help='Target IP address')
    p.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help=f'UDP port to scan (default: {DEFAULT_PORT})')
    p.add_argument('-t', '--timeout', type=int, default=TIMEOUT, help=f'Timeout in seconds (default: {TIMEOUT})')
    p.add_argument('-r', '--retries', type=int, default=0, help='Retries on timeout (default: 0)')
    p.add_argument('--iface', type=str, help='Network interface to use (sets scapy conf.iface)')
    p.add_argument('--sport', type=int, help='Source UDP port to use (helps some NATs)')
    p.add_argument('--natt-first', action='store_true', help='Try NAT-T port 4500 before the given port')
    p.add_argument('-v', '--verbose', action='store_true', help='Verbose output (parse headers, etc.)')
    p.add_argument('-d', '--dump', action='store_true', help='Hex-dump sent/received payloads')
    p.add_argument('-a', '--all', action='store_true', help='Try all methods even after detection')
    return p.parse_args()

def main():
    print_banner()
    args = parse_arguments()

    if args.iface:
        conf.iface = args.iface

    global _SRC_PORT
    _SRC_PORT = args.sport

    if not is_root():
        print(f"{Colors.YELLOW}[!] For reliable results, run as root/Admin (raw sockets).{Colors.ENDC}")

    # Validate IP
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        print(f"{Colors.RED}[-] Invalid IP address: {args.target}{Colors.ENDC}")
        return 1

    print(f"{Colors.BLUE}[*] Target: {args.target}:{args.port}{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Timeout: {args.timeout} seconds • Retries: {args.retries}{Colors.ENDC}")
    if args.sport:
        print(f"{Colors.BLUE}[*] Fixed source port: {args.sport}{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Probing IKE service (v1/v2, NAT-T aware)...{Colors.ENDC}\n")

    methods = [
        method0_simple_udp,       # 1 (non-authoritative)
        method1_ikev1_main,       # 2
        method2_ikev1_aggressive, # 3 (best-effort)
        method3_ikev2_init,       # 4
    ]

    successful = []
    # Decide which ports to try
    if args.natt_first and args.port != 4500:
        ports_to_try = [4500, args.port]
    else:
        ports_to_try = [args.port]
        if args.port == 500:
            ports_to_try.append(4500)  # auto NAT-T fallback

    hit_port = None
    for port_try in ports_to_try:
        for i, m in enumerate(methods, start=1):
            ok = m(args.target, port_try, args.timeout, args.verbose, args.dump, args.retries)
            if ok:
                successful.append(f"{i}@{port_try}")
                hit_port = port_try
                if not args.all:
                    break
            print("")
        if successful and not args.all:
            break

    print(f"{Colors.BLUE}{Colors.BOLD}======== DETECTION SUMMARY ========{Colors.ENDC}")
    if successful:
        port_label = str(hit_port) if hit_port else ( '4500' if any('@4500' in s for s in successful) else str(args.port) )
        primary = successful[0]
        extra = f" (also {', '.join(successful[1:])})" if len(successful) > 1 else ""
        print(f"{Colors.GREEN}[+] IKE service detected on {args.target} (port {port_label}){Colors.ENDC}")
        print(f"{Colors.GREEN}[+] Hit: {primary}{extra}{Colors.ENDC}")
    else:
        tried = ",".join(str(p) for p in ports_to_try)
        print(f"{Colors.RED}[-] No IKE service detected on {args.target} (ports tried: {tried}){Colors.ENDC}")
        print(f"{Colors.YELLOW}[!] Reasons could include:{Colors.ENDC}")
        print(f"{Colors.YELLOW}    - Service not running or on another port{Colors.ENDC}")
        print(f"{Colors.YELLOW}    - Firewall/ACL blocking UDP or malformed packets dropped{Colors.ENDC}")
        print(f"{Colors.YELLOW}    - NAT-T only or device requires stricter proposals{Colors.ENDC}")
    print(f"{Colors.BLUE}{Colors.BOLD}===================================={Colors.ENDC}")
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
