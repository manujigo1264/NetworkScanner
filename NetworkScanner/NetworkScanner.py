import os
import nmap
import socket
import requests
import time
import json
import ipaddress
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='network_scanner.log'
)

def discovery(network_range="192.168.1.0/24", max_threads=10):

    def scan_subnet(subnet):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=subnet, arguments="-sn -n --disable-arp-ping --min-rate=50")
            # Filter out only the hosts explicitly marked as "up"
            live_hosts = []
            for host in nm.all_hosts():
                if 'status' in nm[host] and nm[host]['status']['state'] == 'up':
                    live_hosts.append(host)
            return live_hosts
        except Exception as e:
            print(f"Error during discovery in {subnet}: {e}")
            return []

    # Split the network range into smaller chunks
    chunks = network_range.split(",")  # Use ',' to specify multiple ranges if needed
    results = []

    try:
        with ThreadPoolExecutor(max_threads) as executor:
            for live_hosts in executor.map(scan_subnet, chunks):
                results.extend(live_hosts)
    except Exception as e:
        print(f"Error during concurrent scanning: {e}")

    return results

def full_scan(ip):
    """Combined service detection and OS fingerprinting"""
    services = []
    os_info = None
    
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sV -O --top-ports 100")
        
        # Get OS info
        if 'osmatch' in nm[ip]:
            os_info = nm[ip]['osmatch'][0]['name'] if nm[ip]['osmatch'] else None
        
        # Get services
        for proto in nm[ip].all_protocols():
            for port in sorted(nm[ip][proto].keys()):
                services.append({
                    "port": port,
                    "state": nm[ip][proto][port]["state"],
                    "service": nm[ip][proto][port]["name"],
                    "version": nm[ip][proto][port].get("version", ""),
                    "product": nm[ip][proto][port].get("product", "")
                })
    except Exception as e:
        logging.error(f"Scan failed for {ip}: {e}")
        print(f"Scan failed for {ip}: {e}")
    
    return services, os_info

def validate_network(network_range):
    """Validate network range input"""
    try:
        ipaddress.ip_network(network_range, strict=False)
        return True
    except ValueError:
        return False

def validate_url(url):
    """Basic URL validation"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def check_authorization():
    """Ensure user has authorization to scan"""
    print("\n!! WARNING: Unauthorized network scanning is illegal!")
    print("This tool should only be used on networks you own or have explicit permission to test.\n")
    
    response = input("Do you have authorization to scan this network? (yes/no): ").strip().lower()
    if response != 'yes':
        print("Exiting. Obtain proper authorization before scanning.")
        exit(1)
    
    target_owner = input("Enter target owner/authorization reference: ").strip()
    return target_owner

def port_scan(ip, port_range):
    open_ports = []
    
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)  # Reduced timeout
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return port
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check_port, port_range)
        open_ports = [port for port in results if port is not None]
    
    return open_ports


def vuln_scan(url):
    common_paths = ["/admin", "/login", "/config.php", "/uploads", "/.env", 
                    "/wp-login.php", "/.git/config", "/api/", "/backup"]
    vulnerabilities = []
    
    for path in common_paths:
        try:
            time.sleep(0.5)  # Rate limiting
            full_url = url.rstrip('/') + path
            response = requests.get(full_url, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                vulnerabilities.append({
                    "url": full_url, 
                    "status": response.status_code,
                    "size": len(response.content)
                })
        except requests.exceptions.RequestException as e:
            continue
    
    return vulnerabilities

def reporting_to_file(data, filename="scan_results.json"):
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        print(f"Results saved to {filename}")
        logging.info(f"Results saved to {filename}")
    except Exception as e:
        print(f"Error saving results: {e}")
        logging.error(f"Error saving results: {e}")

def main():
    print("=== Network Security Scanner ===")
    
    # Authorization check
    auth_ref = check_authorization()
    
    # Network discovery
    network_range = input("Enter network range (default 192.168.1.0/24): ").strip() or "192.168.1.0/24"
    
    if not validate_network(network_range):
        print("Invalid network range")
        logging.error(f"Invalid network range: {network_range}")
        return
    
    print(f"\n[*] Starting discovery on {network_range}")
    logging.info(f"Starting discovery on {network_range}")
    active_devices = discovery(network_range)
    print(f"[+] Found {len(active_devices)} active devices")
    logging.info(f"Found {len(active_devices)} active devices: {active_devices}")

    results = {"authorization": auth_ref, "scan_time": str(datetime.now()), "devices": []}
    
    for device in active_devices:
        print(f"\n[*] Scanning {device}")
        logging.info(f"Scanning {device}")
        
        # Port scan with threading
        open_ports = port_scan(device, range(1, 1025))
        print(f"[+] Open ports: {len(open_ports)} - {open_ports}")
        
        # Service detection
        services, os_info = full_scan(device)
        
        print(f"[+] OS: {os_info if os_info else 'Unknown'}")
        for service in services:
            print(f"    Port: {service['port']}, State: {service['state']}, Service: {service['service']}, Version: {service.get('version', 'N/A')}")
        
        results["devices"].append({
            "ip": device,
            "open_ports": open_ports,
            "services": services,
            "os": os_info
        })

    # Vulnerability scan
    url = input("\nEnter URL for vulnerability scan (or press Enter to skip): ").strip()
    if url:
        url = validate_url(url)
        print(f"[*] Scanning {url}")
        logging.info(f"Vulnerability scanning {url}")
        vulnerabilities = vuln_scan(url)
        print(f"\n[+] Found {len(vulnerabilities)} potential vulnerabilities")
        for vuln in vulnerabilities:
            print(f"    {vuln['url']} - Status: {vuln['status']}, Size: {vuln['size']} bytes")
        results["vulnerabilities"] = vulnerabilities

    # Save results
    reporting_to_file(results)
    print("\n[+] Scan complete")
    logging.info("Scan complete")

if __name__ == "__main__":
    main()