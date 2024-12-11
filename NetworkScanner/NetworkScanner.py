import os
import nmap
import socket
import requests
import json


def discovery(network_range="192.168.1.0/24"):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network_range, arguments="-sn")
        return [host for host in nm.all_hosts() if nm[host].state() == "up"]
    except Exception as e:
        print(f"Error during discovery: {e}")
        return []


def port_scan(ip, port_range):
    open_ports = []
    try:
        for port in port_range:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
    except Exception as e:
        print(f"Error during port scanning for {ip}: {e}")
    return open_ports


def service_detection(ip):
    services = []
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sV")
        for proto in nm[ip].all_protocols():
            for port in sorted(nm[ip][proto].keys()):
                state = nm[ip][proto][port]["state"]
                service = nm[ip][proto][port]["name"]
                services.append({"port": port, "state": state, "service": service})
    except Exception as e:
        print(f"Service detection failed for {ip}: {e}")
    return services


def vuln_scan(url):
    common_paths = [
        "/admin",
        "/login",
        "/config.php",
        "/uploads",
        "/.env",
        "/wp-login.php",
    ]
    vulnerabilities = []
    try:
        for path in common_paths:
            full_url = url + path
            if requests.get(full_url, timeout=5).status_code == 200:
                vulnerabilities.append(full_url)
    except Exception as e:
        print(f"Error during vulnerability scan for {url}: {e}")
    return vulnerabilities


def reporting_to_file(data, filename="scan_results.json"):
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"Error saving results: {e}")


def main():
    print("--- Network Scanner ---")
    network_range = (
        input("Enter the network range (default 192.168.1.0/24): ").strip()
        or "192.168.1.0/24"
    )
    active_devices = discovery(network_range)
    print("Active devices:", active_devices)

    results = []
    for device in active_devices:
        print(f"\n--- Processing device: {device} ---")
        open_ports = port_scan(device, range(1, 1025))
        print(f"Open ports for {device}: {open_ports}")
        services = service_detection(device)
        for service in services:
            print(
                f"Port: {service['port']}, State: {service['state']}, Service: {service['service']}"
            )
        results.append(
            {"device": device, "open_ports": open_ports, "services": services}
        )

    url = input(
        "\nEnter the URL for vulnerability scan (or press Enter to skip): "
    ).strip()
    if url:
        vulnerabilities = vuln_scan(url)
        print("\n--- Vulnerability Scan Results ---")
        for vuln in vulnerabilities:
            print(f"Vulnerability: {vuln}")
        results.append({"url": url, "vulnerabilities": vulnerabilities})

    reporting_to_file(results)
    print("\nAll tasks completed.")


if __name__ == "__main__":
    main()