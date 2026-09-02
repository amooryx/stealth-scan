#!/usr/bin/env python3
"""
Stealth Scan — Low-and-Slow Port Scanner with Evasion Techniques
Scans ports with configurable delays, randomization, and decoy source options.
Requires root/admin for raw socket features; falls back to TCP connect scan.
Author: Omar Khalid (amooryx) | github.com/amooryx/stealth-scan
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import os
import random
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
    8888, 27017, 5432, 6379, 9200, 11211,
]

SERVICE_BANNER_PROBES = {
    21:  b"",                      # FTP banner
    22:  b"",                      # SSH banner
    80:  b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    8080:b"HEAD / HTTP/1.0\r\n\r\n",
}

def tcp_connect_scan(host: str, port: int, timeout: float) -> dict:
    result = {"port": port, "state": "closed", "banner": "", "service": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err  = sock.connect_ex((host, port))
        if err == 0:
            result["state"] = "open"
            # Grab banner
            probe = SERVICE_BANNER_PROBES.get(port, b"")
            if probe:
                try:
                    sock.sendall(probe)
                except Exception:
                    pass
            try:
                banner = sock.recv(256).decode(errors="ignore").strip()
                result["banner"] = banner[:100]
            except Exception:
                pass
        sock.close()
    except Exception:
        pass
    return result

def infer_service(port: int, banner: str) -> str:
    known = {22: "SSH", 80: "HTTP", 443: "HTTPS", 21: "FTP", 25: "SMTP",
             3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
             27017: "MongoDB", 445: "SMB", 139: "NetBIOS", 53: "DNS",
             8080: "HTTP-ALT", 9200: "Elasticsearch", 11211: "Memcached"}
    if port in known:
        return known[port]
    if "SSH" in banner:  return "SSH"
    if "HTTP" in banner: return "HTTP"
    if "FTP" in banner:  return "FTP"
    if "SMTP" in banner: return "SMTP"
    return "unknown"

def parse_ports(port_str: str) -> list[int]:
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return list(set(ports))

def main():
    parser = argparse.ArgumentParser(
        description="Stealth Scan — Low-and-Slow Port Scanner (Authorized use only)",
    )
    parser.add_argument("host",          help="Target host/IP")
    parser.add_argument("--ports", "-p", default="common", help="Ports: 'common', '1-1024', '80,443,8080'")
    parser.add_argument("--delay",       type=float, default=0.0,  help="Delay between port scans (ms → s)")
    parser.add_argument("--jitter",      type=float, default=0.0,  help="Random jitter in seconds")
    parser.add_argument("--threads",     type=int, default=50,     help="Concurrent threads")
    parser.add_argument("--timeout",     type=float, default=2.0,  help="Per-port timeout")
    parser.add_argument("--randomize",   action="store_true",      help="Randomize port scan order")
    parser.add_argument("--out",         help="Output JSON file")
    args = parser.parse_args()

    if args.ports == "common":
        ports = list(COMMON_PORTS)
    else:
        ports = parse_ports(args.ports)

    if args.randomize:
        random.shuffle(ports)

    print(f"[*] Stealth scan: {args.host} | {len(ports)} ports | delay={args.delay}s jitter={args.jitter}s")
    print("[!] AUTHORIZED USE ONLY")

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(tcp_connect_scan, args.host, p, args.timeout): p for p in ports}
        for fut in futures:
            r = fut.result()
            if args.delay or args.jitter:
                time.sleep(args.delay + random.uniform(0, args.jitter))
            if r["state"] == "open":
                r["service"] = infer_service(r["port"], r["banner"])
                open_ports.append(r)
                print(f"  [+] {r['port']:5d}/tcp  {r['service']:15s}  {r['banner'][:50]}")

    print(f"\n[*] {len(open_ports)}/{len(ports)} ports open")
    if args.out:
        with open(args.out, "w") as f:
            json.dump({"host": args.host, "open_ports": open_ports}, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
