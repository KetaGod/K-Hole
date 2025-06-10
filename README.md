```
   _  _           _  _      ____      _         ____   
  FJ / ;         FJ  L]    F __ ]    FJ        F ___J  
 J |/ (| ______ J |__| L  J |--| L  J |       J |___:  
 |     L|______||  __  |  | |  | |  | |       | _____| 
 F L:\  L______JF L__J J  F L__J J  F L_____  F L____: 
J__L \__L     J__L  J__LJ\______/FJ________LJ________L
|__L  \L_|     |__L  J__| J______F |________||________|
```

# K-HOLE

**K-HOLE** is an advanced, multi-method network testing and stress simulation toolkit written in Python. Designed for red-team simulations, infrastructure testing, and protocol research, K-HOLE supports a wide range of L4 and L7 methods, recon tools, web vulnerability testers, IoT flooders, and much more.

> ⚠️ **Use K-HOLE only in environments you own or have explicit permission to test.**

---

## 📦 Features Overview

### 🔥 Layer 7 (L7) Attack Methods

* HTTP Flood (Sync & Async)
* WebSocket Flood
* Browser Emulation (Headless Chrome)
* Slowloris
* JS Challenge Bypass (Cloudflare)
* RUDY (R-U-Dead-Yet)
* Custom Header Flood
* SSL Renegotiation Attack
* SMTP Abuse, WebDAV PUT Abuse
* SQL Slam Injection Burst
* DNS Cache Buster

### 💣 Layer 4 (L4) & Protocol Attacks

* UDP / TCP Flood
* ACK/RST Flood
* SYN Cookie Bypass
* Ping of Death / Smurf / Xmas Tree
* IP Spoofed SYN Flood
* Reflected ICMP / GRE Flood
* Fragmentation Flood

### 📡 Amplification (AMP)

* DNS / SSDP / NTP / Memcached
* LDAP / CLDAP / SNMP / VSE (Source Engine)

### 🧠 Utility Tools

* TOR IP Cycling
* Port Scanning
* Payload Editor + Macro Engine
* Interactive Header Builder
* RPS & Thread Calculator
* Live Real-Time Stats Dashboard
* Auto Retry for 403/429 Responses

### 🕵 Recon & Analysis

* Reverse DNS & ASN Lookup
* WHOIS Lookup
* IP Range Scanner
* CDN Detection
* JA3/TLS Fingerprint Generator
* Real IP Resolver (behind proxies)

### 🧬 Protocol-Specific

* Modbus/SCADA Packet Flood
* SIP/VoIP INVITE Flood
* Steam A2S Flood (Source Engine)

### 🧩 Web Application Tools

* Web App Fuzzers for SQLi, XSS, Path Traversal
* Automated payload injection with status code monitor

---

## 🔧 Installation

### 1. Clone the repository

```bash
git clone https://github.com/KetaGod/K-Hole.git
cd K-Hole
```

### 2. Install Python requirements

```bash
pip install -r requirements.txt
```

You may need additional system-level tools for headless browser testing (e.g., Chrome/Chromedriver).

---

## 🖥️ Running K-HOLE

Run with full menu-driven interaction:

```bash
python khole.py
```

Or launch specific attacks via CLI mode:

```bash
python khole.py --mode http --target http://example.com --duration 60 --threads 50
```

---

## 🗂️ Configuration Profiles

You can load `.khcfg` or `.json` profiles that predefine attack parameters:

```json
{
  "mode": "udp",
  "target": "1.2.3.4",
  "port": 80,
  "duration": 120,
  "threads": 100
}
```

---

## 📊 Live Monitoring

Use the built-in dashboard for live stats:

```bash
> Misc Tools > Live Stats Dashboard
```

Displays ongoing metrics for HTTP/TCP/UDP/amplification/etc.

---

## ⚙️ Modules Included

Supports:

* `aiohttp`, `requests`, `cloudscraper`, `websockets`
* `stem`, `ipaddress`, `dnspython`
* `selenium`, `undetected_chromedriver`
* And many others

---

## 🤖 Developer Notes

* All modules are modularized for future expansion
* Easily add new methods by defining and wiring them into the method map
* Built-in utilities assist in header manipulation and payload crafting

---

## 👑 Credits

Coded by **♡KetaGod♡**

* [Telegram](https://t.me/ketagod)
