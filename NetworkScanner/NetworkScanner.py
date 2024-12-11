import os
import nmap
import socket
import requests

# Network Scanner

""" 
1. Discovery module (Idntify active devices on network)
2. Port Scanner (check open ports on devices)
3. Service detection module ( Identify running services)
4. Vulnerability scanner (Identify security flaws)
5. Reporting mechanism (Present results)
"""

def discovery():
    nm = nmap.PortScanner()
    nm.scan(hosts="192.168.1.0/24", arguments="-sn")
    active_devices = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            active_devices.append(host)
    return active_devices


def portScan(ip, port_range):
    open_ports = []
    for port in port_range:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def serviceDetection():
    nm = nmap.PortScanner()
    target = input("Enter the target IP address: ")
    nm.scan(target, arguments="-sV")
    for proto in nm[target].all_protocols():
        lport = nm[target][proto].keys()
        for port in sorted(lport):
            state = nm[target][proto][port]["state"]
            service = nm[target][proto][port]["name"]
            print(f"Port: {port}, State: {state}, Service: {service}")


def vulnScan(url):
    common_paths = [
        "/admin",
        "/login",
        "/config.php",
        "/uploads",
        "/.env",
        "/wp-login.php",
    ]
    vulnerabilities = []

    for path in common_paths:
        full_url = url + path
        response = requests.get(full_url)

        if response.status_code == 200:
            vulnerabilities.append(full_url)

    return vulnerabilities


# Example usage
# results = vulnScan("http://example.com")
# print(results)


def reporting(results):
    for result in results:
        print(f"Result: {result}")


def main():
    active_devices = discovery()
    print("Active devices:", active_devices)

    for device in active_devices:
        print(f"Scanning device: {device}")
        port_range = range(1, 255)  # Example port range
        open_ports = portScan(device, port_range)
        print(f"Open ports for {device}: {open_ports}")
        
        serviceDetection()

    url = input("Enter the URL for vulnerability scan: ")
    vulnerabilities = vulnScan(url)
    reporting(vulnerabilities)

if __name__ == "__main__":
    main()
   
