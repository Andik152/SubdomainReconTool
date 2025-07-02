import asyncio
import aiohttp
import aiodns
import socket
import ipaddress
import argparse
import logging
import json
import csv
from pathlib import Path
from typing import List, Tuple, Dict
import random
import string
import subprocess
import ssl
import sys
import requests
from datetime import datetime
from scapy.all import sniff, TCP, IP, Raw
from scapy.layers.tls.all import TLS, TLSClientHello
from hashlib import md5

# Setup logging
logging.basicConfig(
    filename=f'bypass_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Daftar rentang IP dan org name CDN
CDN_IP_RANGES = {
    "Cloudflare": ["173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13"],
    "Akamai": ["23.32.0.0/11", "23.192.0.0/11"]
}
CDN_ORG_NAMES = {
    "Cloudflare": ["CLOUDFLARE", "CLOUDFLARENET"],
    "Akamai": ["AKAMAI", "AKAMAI TECHNOLOGIES"],
    "Amazon": ["AMAZON", "AWS"]
}
CDN_HEADER_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status"],
    "Akamai": ["akamai-grn", "x-akamai-transformed"],
    "Amazon": ["x-amz-cf-id", "x-amz-cf-pop"]
}

RANDOM_SUBDOMAINS = [''.join(random.choices(string.ascii_lowercase + string.digits, k=15)) for _ in range(5)]

def is_valid_domain(domain: str) -> bool:
    import re
    pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_private_ip(ip: str) -> bool:
    try:
        ip_addr = ipaddress.ip_address(ip)
        return ip_addr.is_private
    except ValueError:
        return False

def is_cdn_ip(ip: str, asn_info: Dict) -> Tuple[bool, str]:
    try:
        ip_addr = ipaddress.ip_address(ip)
        for cdn, ranges in CDN_IP_RANGES.items():
            for cidr in ranges:
                if ip_addr in ipaddress.ip_network(cidr):
                    return True, cdn
        org = asn_info.get("org", "").upper()
        for cdn, org_names in CDN_ORG_NAMES.items():
            if any(name in org for name in org_names):
                return True, cdn
        return False, ""
    except ValueError:
        return False, ""

async def detect_wildcard(domain: str, resolver: aiodns.DNSResolver) -> Tuple[bool, set]:
    wildcard_ips = set()
    for random_sub in RANDOM_SUBDOMAINS:
        try:
            result = await resolver.gethostbyname(f"{random_sub}.{domain}", socket.AF_INET)
            wildcard_ips.update(result.addresses)
        except:
            continue
    return bool(wildcard_ips), wildcard_ips

async def get_passive_subdomains(domain: str, api_key: str = None) -> List[str]:
    if not api_key:
        logging.info("No SecurityTrails API key provided, skipping passive DNS")
        return []
    try:
        headers = {"APIKEY": api_key}
        response = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", headers=headers)
        if response.status_code == 200:
            data = response.json()
            return [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
        else:
            logging.error(f"SecurityTrails API error: {response.status_code}")
            return []
    except Exception as e:
        logging.error(f"Passive DNS lookup failed: {e}")
        return []

async def resolve_dns(subdomain: str, resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore, record_types: List[str] = ["A", "AAAA", "CNAME", "MX"]) -> Dict:
    async with semaphore:
        results = {}
        for rtype in record_types:
            try:
                if rtype == "MX":
                    answers = await resolver.query(subdomain, rtype)
                    results[rtype] = [str(ans.host) for ans in answers]
                else:
                    result = await resolver.gethostbyname(subdomain, socket.AF_INET if rtype == "A" else socket.AF_INET6 if rtype == "AAAA" else socket.AF_INET)
                    results[rtype] = result.addresses
            except Exception as e:
                results[rtype] = []
                logging.debug(f"Failed to resolve {subdomain} ({rtype}): {e}")
        return results

def lookup_asn(ip: str) -> Dict:
    if is_private_ip(ip):
        logging.info(f"Skipping ASN lookup for private IP: {ip}")
        return {"asn": "-", "org": "Private IP", "country": "-"}
    
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        return {
            "asn": results.get("asn", "-"),
            "org": results.get("network", {}).get("name", "-"),
            "country": results.get("network", {}).get("country", "-")
        }
    except ImportError:
        logging.warning("ipwhois not installed, falling back to whois CLI")
    except Exception as e:
        logging.error(f"RDAP lookup failed for {ip}: {e}")
    
    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout.lower()
        asn = org = country = "-"
        for line in output.splitlines():
            if "aut-num:" in line or "origin:" in line:
                asn = line.split(":")[1].strip()
            elif "org-name:" in line or "organization:" in line:
                org = line.split(":")[1].strip()
            elif "country:" in line:
                country = line.split(":")[1].strip()
        return {"asn": asn, "org": org, "country": country}
    except Exception as e:
        logging.error(f"Whois CLI lookup failed for {ip}: {e}")
        return {"asn": "-", "org": "-", "country": "-"}

def compute_ja3_fingerprint(ip: str, port: int = 443, timeout: int = 5) -> str:
    """Compute JA3 fingerprint using Scapy by capturing TLS Client Hello"""
    try:
        # Sniff TLS Client Hello packet
        packets = sniff(
            filter=f"tcp dst port {port} and host {ip}",
            count=1,
            timeout=timeout,
            lfilter=lambda p: p.haslayer(TLS) and p[TLS].haslayer(TLSClientHello)
        )
        if not packets:
            return "ja3:timeout"

        client_hello = packets[0][TLS][TLSClientHello]
        
        # Extract JA3 components
        version = str(client_hello.version)
        ciphers = "-".join(str(cipher) for cipher in client_hello.ciphers)
        extensions = "-".join(str(ext.type) for ext in client_hello.ext if ext)
        elliptic_curves = ""
        ec_point_formats = ""
        for ext in client_hello.ext:
            if ext.type == 10:  # Supported Groups (elliptic curves)
                elliptic_curves = "-".join(str(g) for g in ext.groups)
            elif ext.type == 11:  # EC Point Formats
                ec_point_formats = "-".join(str(f) for f in ext.ecpf)
        
        # Build JA3 string
        ja3_string = f"{version},{ciphers},{extensions},{elliptic_curves},{ec_point_formats}"
        
        # Compute JA3 hash
        ja3_hash = md5(ja3_string.encode()).hexdigest()
        return f"ja3:{ja3_string} ({ja3_hash})"
    except Exception as e:
        logging.error(f"JA3 computation failed for {ip}:{port}: {e}")
        return "ja3:unknown"

async def http_fingerprint(ip: str, port: int, session: aiohttp.ClientSession, use_tls_fingerprint: bool = False) -> Dict:
    url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    result = {
        "port": port,
        "status": None,
        "headers": {},
        "title": "-",
        "final_url": "-",
        "tls_fingerprint": "-",
        "http2": False,
        "cdn_detected": ""
    }

    try:
        if use_tls_fingerprint and port == 443:
            # Compute JA3 fingerprint using Scapy (run in separate thread to avoid blocking)
            loop = asyncio.get_event_loop()
            ja3 = await loop.run_in_executor(None, compute_ja3_fingerprint, ip, port)
            result["tls_fingerprint"] = ja3
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_alpn_protocols(["h2", "http/1.1"])
            context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256")
            async with session.get(url, headers=headers, ssl=context, timeout=8) as resp:
                result["status"] = resp.status
                result["headers"] = dict(resp.headers)
                result["final_url"] = str(resp.url)
                result["http2"] = resp.version == (2, 0)
                try:
                    text = await resp.text()
                    start = text.lower().find("<title>")
                    end = text.lower().find("</title>")
                    if start != -1 and end != -1:
                        result["title"] = text[start + 7:end].strip()
                except:
                    pass
                for cdn, signatures in CDN_HEADER_SIGNATURES.items():
                    if any(sig in result["headers"] for sig in signatures):
                        result["cdn_detected"] = cdn
                        break
        else:
            async with session.get(url, headers=headers, timeout=8, allow_redirects=True) as resp:
                result["status"] = resp.status
                result["headers"] = dict(resp.headers)
                result["final_url"] = str(resp.url)
                result["http2"] = resp.version == (2, 0)
                try:
                    text = await resp.text()
                    start = text.lower().find("<title>")
                    end = text.lower().find("</title>")
                    if start != -1 and end != -1:
                        result["title"] = text[start + 7:end].strip()
                except:
                    pass
                for cdn, signatures in CDN_HEADER_SIGNATURES.items():
                    if any(sig in result["headers"] for sig in signatures):
                        result["cdn_detected"] = cdn
                        break
    except Exception as e:
        logging.debug(f"HTTP check failed for {ip}:{port}: {e}")
    return result

def run_nuclei(ip: str, port: int, output_file: str) -> List[Dict]:
    try:
        cmd = [
            "nuclei", "-u", f"http://{ip}:{port}" if port != 443 else f"https://{ip}",
            "-t", "cves/", "-t", "technologies/", "-jsonl", "-o", output_file
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        findings = []
        with open(output_file, "r") as f:
            for line in f:
                findings.append(json.loads(line.strip()))
        return findings
    except Exception as e:
        logging.error(f"Nuclei scan failed for {ip}:{port}: {e}")
        return []

def parse_ports(port_str: str) -> List[int]:
    ports = []
    for part in port_str.split(','):
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    return sorted(list(set(ports)))

async def process_batch(subdomains: List[str], resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore, wildcard_ips: set) -> List[Dict]:
    tasks = [resolve_dns(sub, resolver, semaphore) for sub in subdomains]
    resolved = await asyncio.gather(*tasks)
    results = []
    for sub, dns_records in zip(subdomains, resolved):
        valid_records = {k: v for k, v in dns_records.items() if v}
        if valid_records:
            for ip in valid_records.get("A", []) + valid_records.get("AAAA", []):
                if ip not in wildcard_ips:
                    asn_info = lookup_asn(ip)
                    is_cdn, cdn_name = is_cdn_ip(ip, asn_info)
                    results.append({
                        "subdomain": sub,
                        "ip": ip,
                        "dns_records": valid_records,
                        "cdn": {"is_cdn": is_cdn, "name": cdn_name},
                        "asn": asn_info
                    })
    return results

def save_results(results: List[Dict], json_file: str, csv_file: str):
    with open(json_file, "w") as f:
        json.dump(results, f, indent=2)
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "subdomain", "ip", "asn", "org", "cdn_name", "port", "status",
            "server", "title", "final_url", "http2", "tls_fingerprint", "cdn_detected", "nuclei_findings"
        ])
        writer.writeheader()
        for result in results:
            writer.writerow({
                "subdomain": result["subdomain"],
                "ip": result["ip"],
                "asn": result["asn"]["asn"],
                "org": result["asn"]["org"],
                "cdn_name": result["cdn"]["name"],
                "port": result.get("http", {}).get("port", "-"),
                "status": result.get("http", {}).get("status", "-"),
                "server": result.get("http", {}).get("headers", {}).get("Server", "-"),
                "title": result.get("http", {}).get("title", "-"),
                "final_url": result.get("http", {}).get("final_url", "-"),
                "http2": str(result.get("http", {}).get("http2", False)),
                "tls_fingerprint": result.get("http", {}).get("tls_fingerprint", "-"),
                "cdn_detected": result.get("http", {}).get("cdn_detected", "-"),
                "nuclei_findings": json.dumps(result.get("nuclei_findings", []))
            })

async def main(domain: str, wordlist_path: str, ports: str, use_tls_fingerprint: bool, use_nuclei: bool, securitytrails_api: str = None):
    print("⚠️ PERINGATAN: Gunakan skrip ini hanya pada domain yang Anda miliki atau dengan izin eksplisit!")
    logging.info(f"Starting scan for domain: {domain}")

    if not is_valid_domain(domain):
        print("Error: Domain tidak valid")
        return

    if not Path(wordlist_path).is_file():
        print(f"Error: File wordlist '{wordlist_path}' tidak ditemukan")
        return

    target_ports = parse_ports(ports)
    if not target_ports:
        print("Error: Port tidak valid")
        return

    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip()]
    subdomains = [f"{w}.{domain}" for w in words]
    if securitytrails_api:
        passive_subdomains = await get_passive_subdomains(domain, securitytrails_api)
        subdomains.extend(passive_subdomains)
        subdomains = list(set(subdomains))
        logging.info(f"Added {len(passive_subdomains)} passive subdomains from SecurityTrails")

    resolver = aiodns.DNSResolver()
    semaphore = asyncio.Semaphore(100)
    has_wildcard, wildcard_ips = await detect_wildcard(domain, resolver)
    if has_wildcard:
        print(f"Wildcard DNS detected for {domain}. IPs: {wildcard_ips}")
        logging.info(f"Wildcard DNS detected: {wildcard_ips}")

    batch_size = 1000
    all_results = []
    for i in range(0, len(subdomains), batch_size):
        batch = subdomains[i:i + batch_size]
        batch_results = await process_batch(batch, resolver, semaphore, wildcard_ips)
        all_results.extend(batch_results)
        print(f"Processed {min(i + batch_size, len(subdomains))}/{len(subdomains)} subdomains")

    if not all_results:
        print("Tidak ditemukan subdomain valid di luar wildcard/CDN")
        logging.info("No valid subdomains found")
        return

    async with aiohttp.ClientSession() as session:
        for result in all_results:
            ip = result["ip"]
            for port in target_ports:
                http_result = await http_fingerprint(ip, port, session, use_tls_fingerprint)
                if http_result["status"]:
                    result["http"] = http_result
                    if use_nuclei:
                        nuclei_output = f"nuclei_{ip}_{port}.jsonl"
                        result["nuclei_findings"] = run_nuclei(ip, port, nuclei_output)
                    break

    json_file = f"results_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    csv_file = f"results_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    save_results(all_results, json_file, csv_file)
    print(f"Results saved to {json_file} and {csv_file}")
    logging.info(f"Results saved to {json_file} and {csv_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Supercharged Cloudflare Origin IP Bypass v2 with Scapy JA3")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("--ports", help="Comma-separated ports or range (e.g., 80,443 or 1-1000)", default="80,443,8080")
    parser.add_argument("--tls-fingerprint", action="store_true", help="Enable TLS fingerprinting for WAF/CDN bypass")
    parser.add_argument("--nuclei", action="store_true", help="Enable Nuclei vulnerability scanning")
    parser.add_argument("--securitytrails-api", help="SecurityTrails API key for passive DNS", default=None)
    args = parser.parse_args()

    try:
        asyncio.run(main(args.domain, args.wordlist, args.ports, args.tls_fingerprint, args.nuclei, args.securitytrails_api))
    except KeyboardInterrupt:
        print("\nScan dihentikan oleh pengguna")
        logging.info("Scan interrupted by user")