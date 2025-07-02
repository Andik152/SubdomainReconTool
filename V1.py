import requests
import socket
import argparse

# Fungsi untuk mencari IP asli server melalui DNS enumeration
def bypass_cloudflare(domain):
    try:
        # Menggunakan tool seperti crt.sh untuk mencari subdomain yang mungkin tidak terproteksi oleh Cloudflare
        response = requests.get(f"https://crt.sh/?q={domain}&output=json")
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                if 'name_value' in entry:
                    subdomain = entry['name_value']
                    try:
                        ip = socket.gethostbyname(subdomain)
                        print(f"Subdomain: {subdomain}, IP: {ip}")
                        return ip
                    except socket.gaierror:
                        continue
    except Exception as e:
        print(f"Error: {e}")
    return None

# Fungsi untuk melakukan port scan pada IP yang ditemukan
def port_scan(ip, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} is open")
            sock.close()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

# Fungsi utama
def main():
    parser = argparse.ArgumentParser(description="Cloudflare Origin Bypass and Port Scan")
    parser.add_argument("domain", help="Target domain")
    args = parser.parse_args()

    domain = args.domain
    print(f"Target domain: {domain}")

    # Mencari IP asli server
    ip = bypass_cloudflare(domain)
    if ip:
        print(f"Found IP: {ip}")
        # Port yang akan di-scan
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080]
        open_ports = port_scan(ip, ports)
        if open_ports:
            print(f"Open ports: {open_ports}")
        else:
            print("No open ports found.")
    else:
        print("Failed to find the origin IP.")

if __name__ == "__main__":
    main()