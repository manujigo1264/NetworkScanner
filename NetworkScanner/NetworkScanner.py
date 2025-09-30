import os
import nmap
import socket
import requests
import time
import json
import ipaddress
import logging
import re
from urllib.parse import urljoin, urlparse
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Scan speed configurations
SCAN_SPEEDS = {
    "stealth": {
        "port_workers": 5,
        "port_timeout": 2.0,
        "port_delay": 0.5,
        "web_delay": 1.0,
        "description": "Very slow, hard to detect"
    },
    "slow": {
        "port_workers": 10,
        "port_timeout": 1.5,
        "port_delay": 0.2,
        "web_delay": 0.5,
        "description": "Slow and cautious"
    },
    "normal": {
        "port_workers": 50,
        "port_timeout": 0.5,
        "port_delay": 0,
        "web_delay": 0.3,
        "description": "Balanced speed and stealth"
    },
    "fast": {
        "port_workers": 100,
        "port_timeout": 0.3,
        "port_delay": 0,
        "web_delay": 0.1,
        "description": "Fast but easily detected"
    },
    "aggressive": {
        "port_workers": 200,
        "port_timeout": 0.2,
        "port_delay": 0,
        "web_delay": 0,
        "description": "Maximum speed, very noisy"
    }
}

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

def port_scan(ip, port_range, speed="normal"):
    """
    Scan ports with configurable speed/stealth settings
    
    Args:
        ip: Target IP address
        port_range: Range of ports to scan
        speed: Scan speed (stealth/slow/normal/fast/aggressive)
    """
    open_ports = []
    config = SCAN_SPEEDS.get(speed, SCAN_SPEEDS["normal"])
    
    def check_port(port):
        try:
            # Add delay for stealth mode
            if config["port_delay"] > 0:
                time.sleep(config["port_delay"])
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(config["port_timeout"])
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return port
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=config["port_workers"]) as executor:
        results = executor.map(check_port, port_range)
        open_ports = [port for port in results if port is not None]
    
    return open_ports

def detect_account_lockout(url, test_username="testuser_nonexistent"):
    """
    Detect if the target has account lockout policies before brute-forcing
    
    Returns:
        dict: {
            "has_lockout": bool,
            "attempts_allowed": int or None,
            "safe_to_test": bool
        }
    """
    print(f"[*] Testing for account lockout policy...")
    
    try:
        response = requests.get(url, timeout=5)
        content_lower = response.text.lower()
        
        # Check if it's a login page
        if not any(x in content_lower for x in ["login", "signin", "username", "password"]):
            return {"has_lockout": False, "attempts_allowed": None, "safe_to_test": False}
        
        # Find form action
        form_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
        if form_match:
            action_url = urljoin(url, form_match.group(1))
        else:
            action_url = url
        
        # Test with invalid credentials multiple times
        print("[*] Sending test authentication attempts...")
        lockout_detected = False
        attempts = 0
        max_test_attempts = 5
        
        for i in range(max_test_attempts):
            try:
                data = {
                    "username": test_username,
                    "password": f"wrongpass{i}",
                    "login": "Login"
                }
                
                test_response = requests.post(action_url, data=data, timeout=5, allow_redirects=False)
                response_text = test_response.text.lower()
                
                # Check for lockout indicators
                lockout_indicators = [
                    "account locked",
                    "account has been locked",
                    "too many attempts",
                    "temporarily locked",
                    "locked out",
                    "try again later",
                    "account disabled",
                    "maximum attempts exceeded",
                    "wait before trying again"
                ]
                
                if any(indicator in response_text for indicator in lockout_indicators):
                    lockout_detected = True
                    attempts = i + 1
                    print(f"[+] Account lockout detected after {attempts} attempts")
                    break
                
                time.sleep(1)  # Wait between attempts
                
            except Exception as e:
                logging.error(f"Error during lockout detection: {e}")
                continue
        
        if lockout_detected:
            return {
                "has_lockout": True,
                "attempts_allowed": attempts,
                "safe_to_test": False,
                "message": f"Account lockout policy detected after {attempts} attempts. Credential testing disabled for safety."
            }
        else:
            # No lockout detected, but still be cautious
            return {
                "has_lockout": False,
                "attempts_allowed": max_test_attempts,
                "safe_to_test": True,
                "message": "No account lockout detected in initial tests. Proceeding with caution."
            }
    
    except Exception as e:
        logging.error(f"Lockout detection failed: {e}")
        return {
            "has_lockout": None,
            "attempts_allowed": None,
            "safe_to_test": False,
            "message": "Unable to determine lockout policy. Credential testing disabled for safety."
        }

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

def content_analysis(url, response):
    """Analyze response content for sensitive information"""
    findings = []
    content = response.text.lower()
    
    # Check for exposed credentials/secrets
    patterns = {
        "Database Credentials": r'(db_password|database_password|mysql_password)[\s:=]+["\']?([^"\'\s]+)',
        "API Keys": r'(api_key|apikey|api_secret)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})',
        "AWS Keys": r'(AKIA[0-9A-Z]{16})',
        "Private Keys": r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)',
        "JWT Tokens": r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
        "Email Addresses": r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        "Internal IPs": r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        "Password Hash": r'(\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53})',
    }
    
    for finding_type, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                "type": finding_type,
                "count": len(matches),
                "severity": "CRITICAL" if "password" in finding_type.lower() or "key" in finding_type.lower() else "HIGH"
            })
    
    # Check for sensitive comments
    if "<!-- todo" in content or "<!-- fix" in content or "<!-- hack" in content:
        findings.append({"type": "Sensitive Comments", "severity": "MEDIUM"})
    
    # Check for debug mode indicators
    if any(x in content for x in ["debug=true", "debug mode", "stack trace", "exception"]):
        findings.append({"type": "Debug Mode Enabled", "severity": "MEDIUM"})
    
    return findings

def sql_injection_test(url):
    """Basic SQL injection vulnerability testing"""
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "1' OR '1'='1",
        "' UNION SELECT NULL--",
        "1 AND 1=1",
        "1 AND 1=2",
    ]
    
    vulnerabilities = []
    
    # Test URL parameters
    parsed = urlparse(url)
    if '?' in url:
        base_url = url.split('?')[0]
        params = url.split('?')[1]
        
        for payload in payloads:
            try:
                test_url = f"{base_url}?{params}{payload}"
                response = requests.get(test_url, timeout=5)
                
                # Check for SQL error messages
                error_indicators = [
                    "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
                    "odbc", "jdbc", "error in your sql", "warning: mysql",
                    "unclosed quotation", "quoted string not properly terminated"
                ]
                
                content_lower = response.text.lower()
                for indicator in error_indicators:
                    if indicator in content_lower:
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "payload": payload,
                            "severity": "CRITICAL",
                            "url": test_url
                        })
                        return vulnerabilities  # Stop after first finding
                
                time.sleep(0.3)  # Rate limiting
            except:
                continue
    
    return vulnerabilities

def xss_test(url):
    """Basic Cross-Site Scripting (XSS) vulnerability testing"""
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
    ]
    
    vulnerabilities = []
    
    # Test URL parameters
    if '?' in url:
        base_url = url.split('?')[0]
        
        for payload in payloads:
            try:
                test_url = f"{base_url}?q={payload}"
                response = requests.get(test_url, timeout=5)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    vulnerabilities.append({
                        "type": "Reflected XSS",
                        "payload": payload,
                        "severity": "HIGH",
                        "url": test_url
                    })
                    return vulnerabilities  # Stop after first finding
                
                time.sleep(0.3)  # Rate limiting
            except:
                continue
    
    return vulnerabilities

def auth_bypass_test(url, max_attempts=3):
    """
    Basic authentication bypass testing with lockout detection
    
    Args:
        url: Target URL
        max_attempts: Maximum credential pairs to test (default: 3)
    """
    bypass_attempts = []
    
    # First, detect account lockout policy
    lockout_info = detect_account_lockout(url)
    
    print(f"[*] Lockout Detection: {lockout_info['message']}")
    logging.info(f"Lockout detection for {url}: {lockout_info}")
    
    if not lockout_info["safe_to_test"]:
        print("[!] Skipping credential testing due to account lockout policy or inability to detect policy")
        return [{
            "type": "Authentication Testing Skipped",
            "reason": lockout_info["message"],
            "severity": "INFO"
        }]
    
    # Limit attempts based on lockout detection
    if lockout_info["attempts_allowed"]:
        max_attempts = min(max_attempts, lockout_info["attempts_allowed"] - 1)
    
    print(f"[*] Testing up to {max_attempts} credential pairs...")
    
    # Common default credentials (limited set)
    default_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("administrator", "administrator"),
    ][:max_attempts]  # Limit to max_attempts
    
    # Try to identify login form
    try:
        response = requests.get(url, timeout=5)
        content_lower = response.text.lower()
        
        # Check if it's a login page
        if any(x in content_lower for x in ["login", "signin", "username", "password"]):
            
            # Find form action
            form_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            if form_match:
                action_url = urljoin(url, form_match.group(1))
            else:
                action_url = url
            
            # Test default credentials
            for username, password in default_creds:
                try:
                    data = {
                        "username": username,
                        "password": password,
                        "login": "Login",
                        "user": username,
                        "pass": password,
                    }
                    
                    login_response = requests.post(action_url, data=data, timeout=5, allow_redirects=False)
                    
                    # Check for successful login indicators
                    if login_response.status_code in [200, 302]:
                        response_text = login_response.text.lower()
                        if any(x in response_text for x in ["dashboard", "welcome", "logout", "profile"]):
                            bypass_attempts.append({
                                "type": "Weak Default Credentials",
                                "username": username,
                                "password": password,
                                "severity": "CRITICAL"
                            })
                            print(f"[!] CRITICAL: Successful login with {username}:{password}")
                            return bypass_attempts
                    
                    time.sleep(2)  # Significant delay between attempts
                except Exception as e:
                    logging.error(f"Error testing credentials {username}: {e}")
                    continue
    except Exception as e:
        logging.error(f"Authentication bypass test error: {e}")
    
    return bypass_attempts

def discover_subdirectories(url, wordlist=None, delay=0.2):
    """Discover hidden subdirectories with configurable delay"""
    if wordlist is None:
        wordlist = [
            "admin", "login", "dashboard", "api", "backup", "backups",
            "config", "uploads", "upload", "images", "img", "css", "js",
            "includes", "inc", "lib", "src", "test", "tests", "tmp",
            "temp", "cache", "logs", "old", "new", "dev", "staging",
            "beta", "alpha", "private", "secret", "hidden", "data",
            "db", "database", "sql", "mysql", "phpmyadmin", "pma",
            "wp-admin", "wp-content", "wp-includes", "wordpress",
            "admin/login", "user/login", "api/v1", "api/v2"
        ]
    
    discovered = []
    
    for path in wordlist:
        try:
            full_url = urljoin(url.rstrip('/') + '/', path)
            response = requests.get(full_url, timeout=3, allow_redirects=False)
            
            if response.status_code in [200, 403, 301, 302]:
                discovered.append({
                    "url": full_url,
                    "status": response.status_code,
                    "size": len(response.content),
                    "accessible": response.status_code == 200
                })
            
            time.sleep(delay)  # Configurable rate limiting
        except:
            continue
    
    return discovered

def sql_injection_test(url, delay=0.3):
    """Basic SQL injection vulnerability testing with configurable delay"""
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "1' OR '1'='1",
        "' UNION SELECT NULL--",
        "1 AND 1=1",
        "1 AND 1=2",
    ]
    
    vulnerabilities = []
    
    if '?' in url:
        base_url = url.split('?')[0]
        params = url.split('?')[1]
        
        for payload in payloads:
            try:
                test_url = f"{base_url}?{params}{payload}"
                response = requests.get(test_url, timeout=5)
                
                error_indicators = [
                    "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
                    "odbc", "jdbc", "error in your sql", "warning: mysql",
                    "unclosed quotation", "quoted string not properly terminated"
                ]
                
                content_lower = response.text.lower()
                for indicator in error_indicators:
                    if indicator in content_lower:
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "payload": payload,
                            "severity": "CRITICAL",
                            "url": test_url
                        })
                        return vulnerabilities
                
                time.sleep(delay)  # Configurable delay
            except:
                continue
    
    return vulnerabilities

def xss_test(url, delay=0.3):
    """Basic XSS vulnerability testing with configurable delay"""
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
    ]
    
    vulnerabilities = []
    
    if '?' in url:
        base_url = url.split('?')[0]
        
        for payload in payloads:
            try:
                test_url = f"{base_url}?q={payload}"
                response = requests.get(test_url, timeout=5)
                
                if payload in response.text:
                    vulnerabilities.append({
                        "type": "Reflected XSS",
                        "payload": payload,
                        "severity": "HIGH",
                        "url": test_url
                    })
                    return vulnerabilities
                
                time.sleep(delay)  # Configurable delay
            except:
                continue
    
    return vulnerabilities

def detect_technology(url):
    """Detect web technologies in use"""
    technologies = []
    
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        content = response.text.lower()
        
        # Check headers
        if 'X-Powered-By' in headers:
            technologies.append(f"Powered by: {headers['X-Powered-By']}")
        
        if 'Server' in headers:
            technologies.append(f"Server: {headers['Server']}")
        
        # Check content for CMS/frameworks
        tech_patterns = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Joomla": ["joomla", "com_content"],
            "Drupal": ["drupal", "sites/default"],
            "Laravel": ["laravel", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "React": ["react", "__react"],
            "Angular": ["ng-version", "angular"],
            "Vue.js": ["vue", "v-cloak"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
        }
        
        for tech, patterns in tech_patterns.items():
            if any(pattern in content for pattern in patterns):
                technologies.append(tech)
        
    except:
        pass
    
    return technologies

def enhanced_vuln_scan(url, scan_speed="normal"):
    """Enhanced vulnerability scanner with all features"""
    print(f"\n[*] Starting enhanced vulnerability scan on {url}")
    
    config = SCAN_SPEEDS.get(scan_speed, SCAN_SPEEDS["normal"])
    web_delay = config["web_delay"]
    
    all_findings = {
        "url": url,
        "scan_time": str(datetime.now()),
        "scan_speed": scan_speed,
        "technologies": [],
        "exposed_paths": [],
        "subdirectories": [],
        "content_analysis": [],
        "sql_injection": [],
        "xss": [],
        "auth_bypass": [],
    }
    
    # 1. Detect technologies
    print("[*] Detecting technologies...")
    all_findings["technologies"] = detect_technology(url)
    print(f"[+] Technologies detected: {', '.join(all_findings['technologies']) if all_findings['technologies'] else 'None'}")
    
    # 2. Directory discovery
    print("[*] Discovering subdirectories...")
    all_findings["subdirectories"] = discover_subdirectories(url, delay=web_delay)
    print(f"[+] Found {len(all_findings['subdirectories'])} directories")
    
    # 3. Check common paths (including 403)
    common_paths = [
        "/admin", "/login", "/config.php", "/uploads", "/.env",
        "/wp-login.php", "/.git/config", "/api/", "/backup",
        "/.git/HEAD", "/phpinfo.php", "/server-status",
        "/wp-config.php", "/database.sql", "/.htaccess",
        "/robots.txt", "/sitemap.xml", "/debug", "/test",
        "/.env.backup", "/.env.old", "/config.json", "/settings.json"
    ]
    
    print("[*] Checking for exposed files...")
    for path in common_paths:
        try:
            time.sleep(web_delay)  # Use configurable delay
            full_url = url.rstrip('/') + path
            response = requests.get(full_url, timeout=5, allow_redirects=False)
            
            if response.status_code in [200, 403]:
                finding = {
                    "url": full_url,
                    "status": response.status_code,
                    "size": len(response.content),
                    "severity": "CRITICAL" if response.status_code == 200 else "MEDIUM"
                }
                
                # Content analysis for 200 responses
                if response.status_code == 200:
                    content_findings = content_analysis(full_url, response)
                    if content_findings:
                        finding["content_findings"] = content_findings
                
                all_findings["exposed_paths"].append(finding)
        except:
            continue
    
    print(f"[+] Found {len(all_findings['exposed_paths'])} exposed paths")
    
    # 4. SQL Injection testing
    print("[*] Testing for SQL injection vulnerabilities...")
    all_findings["sql_injection"] = sql_injection_test(url, delay=web_delay)
    if all_findings["sql_injection"]:
        print(f"[!] SQL Injection vulnerability detected!")
    
    # 5. XSS testing
    print("[*] Testing for XSS vulnerabilities...")
    all_findings["xss"] = xss_test(url, delay=web_delay)
    if all_findings["xss"]:
        print(f"[!] XSS vulnerability detected!")
    
    # 6. Authentication bypass testing with lockout detection
    print("[*] Testing for authentication bypass...")
    all_findings["auth_bypass"] = auth_bypass_test(url)
    
    return all_findings

def udp_port_scan(ip, port_list=None, speed="normal"):
    """
    UDP port scanning (much harder than TCP)
    """
    if port_list is None:
        # Common UDP ports
        port_list = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 389, 
                     445, 500, 514, 520, 631, 1434, 1900, 4500, 5353]
    
    config = SCAN_SPEEDS.get(speed, SCAN_SPEEDS["normal"])
    open_ports = []
    
    def check_udp_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(config["port_timeout"] * 2)  # UDP needs longer
            
            # Send empty packet
            sock.sendto(b'', (ip, port))
            
            try:
                # If we get ICMP port unreachable, port is closed
                data, addr = sock.recvfrom(1024)
                sock.close()
                return port  # Port is open (got response)
            except socket.timeout:
                # Timeout could mean open or filtered
                sock.close()
                return port  # Assume open/filtered
            
        except socket.error:
            return None
        
        return None
    
    with ThreadPoolExecutor(max_workers=config["port_workers"] // 2) as executor:
        results = executor.map(check_udp_port, port_list)
        open_ports = [port for port in results if port is not None]
    
    return open_ports

def banner_grab(ip, port, timeout=3):
    """
    Grab service banner for detailed fingerprinting
    """
    banners = {
        21: b"USER anonymous\r\n",  # FTP
        22: b"",  # SSH (sends banner immediately)
        25: b"EHLO test\r\n",  # SMTP
        80: b"GET / HTTP/1.0\r\n\r\n",  # HTTP
        110: b"",  # POP3
        143: b"",  # IMAP
        443: b"",  # HTTPS (needs TLS)
        3306: b"\x00",  # MySQL
        5432: b"",  # PostgreSQL
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send appropriate probe
        if port in banners:
            sock.send(banners[port])
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return {
            "port": port,
            "banner": banner,
            "service": identify_service_from_banner(banner, port)
        }
    except:
        return None

def identify_service_from_banner(banner, port):
    """
    Identify service from banner text
    """
    banner_lower = banner.lower()
    
    if "ssh" in banner_lower:
        return f"SSH ({banner.split()[0]})"
    elif "http" in banner_lower or "html" in banner_lower:
        return "HTTP Server"
    elif "ftp" in banner_lower:
        return f"FTP ({banner.split()[0]})"
    elif "smtp" in banner_lower or "mail" in banner_lower:
        return "SMTP Mail Server"
    elif "mysql" in banner_lower:
        return "MySQL Database"
    elif "postgresql" in banner_lower:
        return "PostgreSQL Database"
    elif "microsoft" in banner_lower:
        return "Microsoft Service"
    else:
        return f"Unknown (Port {port})"

def detect_firewall(ip):
    """
    Detect firewall/IDS by analyzing scan responses
    """
    print(f"[*] Testing for firewall/IDS on {ip}")
    
    firewall_indicators = {
        "filtered_ports": 0,
        "rst_packets": 0,
        "no_response": 0,
        "likely_filtered": False
    }
    
    # Test common ports with different techniques
    test_ports = [21, 22, 23, 25, 80, 443, 3389, 8080]
    
    for port in test_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            
            if result == 111:  # Connection refused
                firewall_indicators["rst_packets"] += 1
            elif result != 0:  # Timeout or filtered
                firewall_indicators["no_response"] += 1
            
            sock.close()
            time.sleep(0.1)
        except:
            firewall_indicators["filtered_ports"] += 1
    
    # Analysis
    if firewall_indicators["no_response"] > 5:
        firewall_indicators["likely_filtered"] = True
        firewall_indicators["detection"] = "Possible stateful firewall detected (timeouts)"
    elif firewall_indicators["rst_packets"] > 6:
        firewall_indicators["detection"] = "Host is up but all ports closed/filtered"
    else:
        firewall_indicators["detection"] = "No obvious filtering detected"
    
    print(f"[+] Firewall Detection: {firewall_indicators['detection']}")
    return firewall_indicators

def passive_os_fingerprint(ip, port):
    """
    Passive OS fingerprinting using TCP/IP stack characteristics
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        
        # Get TCP options (requires raw socket access on Windows)
        # This is simplified - full implementation needs scapy
        
        sock.close()
        
        # Analyze TTL, Window Size, etc.
        # Common TTL values:
        # Linux: 64
        # Windows: 128
        # Cisco: 255
        
        return {
            "os_guess": "Requires elevated privileges for full fingerprinting",
            "method": "TCP/IP stack analysis"
        }
    except:
        return None

def traceroute(target, max_hops=30):
    """
    Trace network path to target
    """
    print(f"[*] Tracing route to {target}")
    route = []
    
    for ttl in range(1, max_hops + 1):
        try:
            # Create ICMP socket (requires root/admin on most systems)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.settimeout(2)
            
            # Send ICMP echo request
            sock.sendto(b'', (target, 1))
            
            try:
                data, addr = sock.recvfrom(512)
                route.append({
                    "hop": ttl,
                    "ip": addr[0],
                    "hostname": socket.gethostbyaddr(addr[0])[0] if addr[0] else "Unknown"
                })
                
                if addr[0] == target:
                    break
            except socket.timeout:
                route.append({"hop": ttl, "ip": "*", "hostname": "Request timed out"})
            
            sock.close()
        except PermissionError:
            return {"error": "Traceroute requires administrator/root privileges"}
        except Exception as e:
            route.append({"hop": ttl, "error": str(e)})
    
    return route



def get_mac_address(ip):
    """
    Get MAC address for local network hosts (ARP)
    """
    try:
        # Use ARP to get MAC address (only works on local network)
        import subprocess
        
        # Windows
        if os.name == 'nt':
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
            # Parse ARP output
            for line in output.split('\n'):
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        mac = parts[1]
                        return {
                            "ip": ip,
                            "mac": mac,
                            "vendor": lookup_mac_vendor(mac)
                        }
        # Linux/Mac
        else:
            output = subprocess.check_output(f"arp -n {ip}", shell=True).decode()
            for line in output.split('\n'):
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        mac = parts[2]
                        return {
                            "ip": ip,
                            "mac": mac,
                            "vendor": lookup_mac_vendor(mac)
                        }
    except:
        pass
    
    return None

def ssl_tls_scan(hostname, port=443):
    """
    Comprehensive SSL/TLS security testing
    """
    import ssl
    
    results = {
        "hostname": hostname,
        "port": port,
        "certificate": {},
        "protocols": {},
        "ciphers": [],
        "vulnerabilities": []
    }
    
    try:
        # Get certificate info
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                results["certificate"] = {
                    "subject": dict(x[0] for x in cert['subject']),
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "version": cert['version'],
                    "notBefore": cert['notBefore'],
                    "notAfter": cert['notAfter'],
                    "serialNumber": cert['serialNumber']
                }
                
                # Check certificate expiry
                from datetime import datetime
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry - datetime.now()).days
                
                if days_until_expiry < 30:
                    results["vulnerabilities"].append({
                        "type": "Certificate Expiring Soon",
                        "severity": "HIGH",
                        "details": f"Expires in {days_until_expiry} days"
                    })
                
                # Get protocol version
                results["protocol_version"] = ssock.version()
        
        # Test for weak protocols (SSLv2, SSLv3, TLSv1.0)
        weak_protocols = {
            ssl.PROTOCOL_SSLv23: "SSLv2/v3",
            ssl.PROTOCOL_TLSv1: "TLSv1.0",
        }
        
        for protocol, name in weak_protocols.items():
            try:
                context = ssl.SSLContext(protocol)
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        results["vulnerabilities"].append({
                            "type": f"Weak Protocol Supported: {name}",
                            "severity": "HIGH"
                        })
            except:
                pass
        
        # Check for common vulnerabilities
        # POODLE, BEAST, CRIME, Heartbleed detection would go here
        
    except Exception as e:
        results["error"] = str(e)
    
    return results

def lookup_mac_vendor(mac):
    """
    Lookup MAC address vendor (first 3 octets)
    """
    # Simplified - full implementation would use OUI database
    vendors = {
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5d": "Microsoft Hyper-V",
        "00:1c:42": "Parallels",
    }
    
    prefix = mac[:8].lower()
    return vendors.get(prefix, "Unknown Vendor")

def dns_enumeration(domain):
    """
    Comprehensive DNS record enumeration
    """
    import dns.resolver
    
    print(f"[*] Enumerating DNS records for {domain}")
    
    records = {
        "domain": domain,
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "SOA": [],
        "CNAME": [],
        "subdomains": []
    }
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                records[record_type].append(str(rdata))
        except:
            pass
    
    # Subdomain enumeration
    common_subdomains = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", 
        "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
        "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin",
        "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
        "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop"
    ]
    
    print(f"[*] Testing {len(common_subdomains)} common subdomains...")
    for subdomain in common_subdomains:
        try:
            full_domain = f"{subdomain}.{domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            records["subdomains"].append({
                "subdomain": full_domain,
                "ip": [str(rdata) for rdata in answers]
            })
        except:
            pass
        time.sleep(0.1)
    
    print(f"[+] Found {len(records['subdomains'])} subdomains")
    return records

def snmp_scan(ip, community_strings=None):
    """
    SNMP enumeration (requires pysnmp)
    """
    if community_strings is None:
        community_strings = ["public", "private", "community"]
    
    results = {
        "ip": ip,
        "snmp_enabled": False,
        "community_string": None,
        "system_info": {}
    }
    
    # Common SNMP OIDs
    oids = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
        "sysContact": "1.3.6.1.2.1.1.4.0"
    }
    
    # This is simplified - full implementation needs pysnmp
    print(f"[*] Testing SNMP on {ip}")
    print("[!] Full SNMP implementation requires 'pysnmp' library")
    
    return results

def smb_enumeration(ip):
    """
    SMB/NetBIOS enumeration for Windows hosts
    """
    import subprocess
    
    results = {
        "ip": ip,
        "netbios_name": None,
        "workgroup": None,
        "shares": [],
        "users": [],
        "os_version": None
    }
    
    try:
        # Use nmblookup or smbclient (Linux) or net view (Windows)
        if os.name == 'nt':
            # Windows
            output = subprocess.check_output(f"nbtstat -A {ip}", shell=True, timeout=5).decode()
            # Parse output for NetBIOS name
            for line in output.split('\n'):
                if "<00>" in line and "UNIQUE" in line:
                    results["netbios_name"] = line.split()[0]
                elif "<00>" in line and "GROUP" in line:
                    results["workgroup"] = line.split()[0]
        else:
            # Linux - requires smbclient
            output = subprocess.check_output(f"nmblookup -A {ip}", shell=True, timeout=5).decode()
            # Parse output
            for line in output.split('\n'):
                if "<00>" in line:
                    parts = line.split()
                    if len(parts) > 0:
                        results["netbios_name"] = parts[0]
        
        # Enumerate shares
        if os.name == 'nt':
            try:
                shares_output = subprocess.check_output(f"net view \\\\{ip}", shell=True, timeout=5).decode()
                for line in shares_output.split('\n'):
                    if "Disk" in line or "IPC" in line:
                        share_name = line.split()[0]
                        results["shares"].append(share_name)
            except:
                pass
        
    except subprocess.TimeoutExpired:
        results["error"] = "SMB enumeration timed out"
    except Exception as e:
        results["error"] = str(e)
    
    return results

def comprehensive_scan(ip, speed="normal"):
    """
    Run all scanning techniques on a single host
    """
    print(f"\n{'='*60}")
    print(f"COMPREHENSIVE SCAN: {ip}")
    print(f"{'='*60}")
    
    results = {
        "ip": ip,
        "scan_time": str(datetime.now()),
        "speed": speed
    }
    
    # 1. Firewall detection
    results["firewall"] = detect_firewall(ip)
    
    # 2. TCP port scan
    print("\n[*] TCP Port Scanning...")
    results["tcp_ports"] = port_scan(ip, range(1, 1025), speed=speed)
    print(f"[+] Found {len(results['tcp_ports'])} open TCP ports")
    
    # 3. UDP port scan (common ports only)
    print("\n[*] UDP Port Scanning...")
    results["udp_ports"] = udp_port_scan(ip, speed=speed)
    print(f"[+] Found {len(results['udp_ports'])} open UDP ports")
    
    # 4. Banner grabbing on open TCP ports
    print("\n[*] Banner Grabbing...")
    results["banners"] = []
    for port in results["tcp_ports"][:20]:  # Limit to first 20
        banner = banner_grab(ip, port)
        if banner:
            results["banners"].append(banner)
            print(f"[+] Port {port}: {banner['service']}")
    
    # 5. Service detection with nmap
    print("\n[*] Service Detection...")
    services, os_info = full_scan(ip)
    results["services"] = services
    results["os"] = os_info
    
    # 6. MAC address (if local network)
    results["mac"] = get_mac_address(ip)
    
    # 7. SMB enumeration (if port 445 or 139 open)
    if 445 in results["tcp_ports"] or 139 in results["tcp_ports"]:
        print("\n[*] SMB Enumeration...")
        results["smb"] = smb_enumeration(ip)
    
    # 8. SSL/TLS scan (if port 443 open)
    if 443 in results["tcp_ports"]:
        print("\n[*] SSL/TLS Security Scan...")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            results["ssl_tls"] = ssl_tls_scan(hostname)
        except:
            print("[!] Could not resolve hostname for SSL scan")
    
    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}\n")
    
    return results

def reporting_to_file(data, filename="scan_results.json"):
    """
    Save comprehensive scan results with better formatting
    """
    try:
        # Adjust filename based on mode
        if data.get("scan_mode") == "OSCP-Compliant":
            filename = "oscp_enum_results.json"
            summary_filename = "oscp_enum_summary.txt"
        else:
            summary_filename = "scan_results_summary.txt"
        
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        print(f"\n[+] Results saved to {filename}")
        logging.info(f"Results saved to {filename}")
        
        # Generate text summary
        generate_text_summary(data, summary_filename)
        print(f"[+] Summary report saved to {summary_filename}")
        
    except Exception as e:
        print(f"Error saving results: {e}")
        logging.error(f"Error saving results: {e}")

def generate_text_summary(data, filename):
    """
    Generate human-readable text summary report
    """
    try:
        with open(filename, "w") as f:
            f.write("="*70 + "\n")
            f.write("NETWORK SECURITY SCAN REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Authorization: {data.get('authorization', 'N/A')}\n")
            f.write(f"Scan Time: {data.get('scan_time', 'N/A')}\n")
            f.write(f"Scan Speed: {data.get('scan_speed', 'N/A')}\n")
            f.write(f"Scan Type: {data.get('scan_type', 'N/A')}\n\n")
            
            f.write("-"*70 + "\n")
            f.write("DISCOVERED HOSTS\n")
            f.write("-"*70 + "\n\n")
            
            for device in data.get("devices", []):
                ip = device.get("ip", "Unknown")
                details = device.get("scan_details", {})
                
                f.write(f"\nHost: {ip}\n")
                f.write("="*70 + "\n")
                
                # TCP Ports
                tcp_ports = details.get("tcp_ports", [])
                if tcp_ports:
                    f.write(f"  Open TCP Ports ({len(tcp_ports)}): {', '.join(map(str, tcp_ports))}\n")
                
                # UDP Ports
                udp_ports = details.get("udp_ports", [])
                if udp_ports:
                    f.write(f"  Open UDP Ports ({len(udp_ports)}): {', '.join(map(str, udp_ports))}\n")
                
                # OS
                os_info = details.get("os")
                if os_info:
                    f.write(f"  Operating System: {os_info}\n")
                
                # MAC
                mac_info = details.get("mac")
                if mac_info:
                    f.write(f"  MAC Address: {mac_info.get('mac', 'N/A')} ({mac_info.get('vendor', 'Unknown')})\n")
                
                # Services
                services = details.get("services", [])
                if services:
                    f.write(f"\n  Services Detected:\n")
                    for svc in services[:15]:  # First 15
                        f.write(f"    Port {svc['port']}: {svc['service']} {svc.get('version', '')}\n")
                
                # Banners
                banners = details.get("banners", [])
                if banners:
                    f.write(f"\n  Service Banners:\n")
                    for banner in banners[:10]:
                        f.write(f"    Port {banner['port']}: {banner.get('banner', 'No banner')[:60]}\n")
                
                # SMB
                smb = details.get("smb", {})
                if smb.get("netbios_name"):
                    f.write(f"\n  SMB Information:\n")
                    f.write(f"    NetBIOS Name: {smb['netbios_name']}\n")
                    f.write(f"    Workgroup: {smb.get('workgroup', 'Unknown')}\n")
                    if smb.get("shares"):
                        f.write(f"    Shares: {', '.join(smb['shares'])}\n")
                
                # SSL/TLS
                ssl_tls = details.get("ssl_tls", {})
                if ssl_tls.get("certificate"):
                    f.write(f"\n  SSL/TLS Information:\n")
                    cert = ssl_tls["certificate"]
                    f.write(f"    Subject: {cert.get('subject', {}).get('commonName', 'N/A')}\n")
                    f.write(f"    Issuer: {cert.get('issuer', {}).get('commonName', 'N/A')}\n")
                    f.write(f"    Valid Until: {cert.get('notAfter', 'N/A')}\n")
                
                # Firewall
                firewall = details.get("firewall", {})
                if firewall.get("detection"):
                    f.write(f"\n  Firewall Detection: {firewall['detection']}\n")
                
                f.write("\n")
            
            # Web Vulnerabilities
            web_vuln = data.get("web_vulnerabilities", {})
            if web_vuln:
                f.write("\n" + "-"*70 + "\n")
                f.write("WEB APPLICATION VULNERABILITIES\n")
                f.write("-"*70 + "\n\n")
                
                f.write(f"Target URL: {web_vuln.get('url', 'N/A')}\n\n")
                
                if web_vuln.get("technologies"):
                    f.write(f"Technologies: {', '.join(web_vuln['technologies'])}\n\n")
                
                if web_vuln.get("exposed_paths"):
                    f.write(f"Exposed Paths ({len(web_vuln['exposed_paths'])}):\n")
                    for path in web_vuln["exposed_paths"]:
                        f.write(f"  [{path['severity']}] {path['url']} (Status: {path['status']})\n")
                        if path.get("content_findings"):
                            for finding in path["content_findings"]:
                                f.write(f"    - {finding['type']} ({finding['severity']})\n")
                    f.write("\n")
                
                if web_vuln.get("sql_injection"):
                    f.write("SQL Injection Vulnerabilities:\n")
                    for vuln in web_vuln["sql_injection"]:
                        f.write(f"  [CRITICAL] {vuln['type']}\n")
                        f.write(f"    Payload: {vuln['payload']}\n")
                    f.write("\n")
                
                if web_vuln.get("xss"):
                    f.write("XSS Vulnerabilities:\n")
                    for vuln in web_vuln["xss"]:
                        f.write(f"  [HIGH] {vuln['type']}\n")
                        f.write(f"    Payload: {vuln['payload']}\n")
                    f.write("\n")
                
                if web_vuln.get("auth_bypass"):
                    f.write("Authentication Issues:\n")
                    for vuln in web_vuln["auth_bypass"]:
                        if vuln["type"] != "Authentication Testing Skipped":
                            f.write(f"  [CRITICAL] {vuln['type']}: {vuln['username']}:{vuln['password']}\n")
                    f.write("\n")
            
            # DNS Enumeration
            dns = data.get("dns_enumeration", {})
            if dns:
                f.write("\n" + "-"*70 + "\n")
                f.write("DNS ENUMERATION\n")
                f.write("-"*70 + "\n\n")
                
                f.write(f"Domain: {dns.get('domain', 'N/A')}\n\n")
                
                for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                    records = dns.get(record_type, [])
                    if records:
                        f.write(f"{record_type} Records:\n")
                        for record in records:
                            f.write(f"  {record}\n")
                        f.write("\n")
                
                subdomains = dns.get("subdomains", [])
                if subdomains:
                    f.write(f"Discovered Subdomains ({len(subdomains)}):\n")
                    for subdomain in subdomains:
                        f.write(f"  {subdomain['subdomain']}: {', '.join(subdomain['ip'])}\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*70 + "\n")
            
    except Exception as e:
        logging.error(f"Error generating text summary: {e}")

def oscp_compliant_scan(ip, speed="normal"):
    """
    OSCP-compliant enumeration (NO automated exploitation)
    """
    print(f"\n{'='*60}")
    print(f"OSCP-COMPLIANT ENUMERATION: {ip}")
    print(f"{'='*60}")
    
    results = {
        "ip": ip,
        "scan_time": str(datetime.now()),
    }
    
    # 1. Host discovery
    print("[*] Checking if host is alive...")
    # ... discovery code
    
    # 2. TCP Port Scanning - ALLOWED
    print("[*] TCP Port Scanning...")
    results["tcp_ports"] = port_scan(ip, range(1, 65536), speed=speed)
    
    # 3. UDP Port Scanning - ALLOWED  
    print("[*] UDP Port Scanning (common ports)...")
    results["udp_ports"] = udp_port_scan(ip, speed=speed)
    
    # 4. Service Detection - ALLOWED (like nmap -sV)
    print("[*] Service Version Detection...")
    results["services"], results["os"] = full_scan(ip)
    
    # 5. Banner Grabbing - ALLOWED
    print("[*] Banner Grabbing...")
    results["banners"] = []
    for port in results["tcp_ports"][:20]:
        banner = banner_grab(ip, port)
        if banner:
            results["banners"].append(banner)
    
    # 6. SMB Enumeration - ALLOWED (like enum4linux)
    if 445 in results["tcp_ports"] or 139 in results["tcp_ports"]:
        print("[*] SMB Enumeration...")
        results["smb"] = smb_enumeration(ip)
    
    # 7. SSL/TLS Information - ALLOWED
    if 443 in results["tcp_ports"]:
        print("[*] SSL/TLS Enumeration...")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            results["ssl"] = ssl_tls_scan(hostname)
        except:
            pass
    
    # 8. Network Analysis - ALLOWED
    results["firewall"] = detect_firewall(ip)
    results["mac"] = get_mac_address(ip)
    
    print("\n[!] ENUMERATION COMPLETE")
    print("[!] Manual exploitation required - no automated vulnerability testing performed")
    
    return results

def oscp_web_enum(url):
    """
    OSCP-compliant web enumeration (NO automated exploitation)
    """
    print(f"\n[*] Web Enumeration: {url}")
    
    results = {
        "url": url,
        "technologies": [],
        "directories": [],
        "files": []
    }
    
    # 1. Technology Detection - ALLOWED
    print("[*] Detecting Technologies...")
    results["technologies"] = detect_technology(url)
    
    # 2. Directory Enumeration - ALLOWED (like gobuster)
    print("[*] Directory Enumeration...")
    results["directories"] = discover_subdirectories(url)
    
    # 3. Common File Discovery - ALLOWED
    print("[*] Common File Discovery...")
    common_files = [
        "/robots.txt", "/sitemap.xml", "/.htaccess",
        "/readme.txt", "/changelog.txt", "/license.txt"
    ]
    
    for file in common_files:
        try:
            response = requests.get(url + file, timeout=5)
            if response.status_code == 200:
                results["files"].append({
                    "file": file,
                    "size": len(response.content)
                })
        except:
            pass
    
    print("\n[!] WEB ENUMERATION COMPLETE")
    print("[!] Manual vulnerability testing required")
    
    # DO NOT test for SQLi, XSS, auth bypass automatically!
    
    return results

def main():
    print("=== Network Security Scanner ===")
    
    # Authorization check
    auth_ref = check_authorization()
    
    # Select scan mode
    print("\n=== Scan Mode Selection ===")
    print("1. Full Security Scan (Includes automated vulnerability testing)")
    print("2. OSCP-Compliant Scan (Enumeration only - NO automated exploitation)")
    
    scan_mode = input("\nSelect scan mode (default: 1): ").strip() or "1"
    
    if scan_mode == "2":
        print("\n[+] OSCP-COMPLIANT MODE ACTIVATED")
        print("[!] Automated vulnerability testing DISABLED")
        print("[!] Manual exploitation required for all findings")
        oscp_mode = True
    else:
        print("\n[+] Full Security Scan Mode")
        oscp_mode = False
    
    # Select scan type (if not OSCP mode)
    if not oscp_mode:
        print("\n=== Scan Type Selection ===")
        print("1. Quick Scan (TCP ports only)")
        print("2. Standard Scan (TCP + services)")
        print("3. Full Scan (TCP + UDP + services + banners)")
        print("4. Comprehensive Scan (Everything including SSL/SMB/DNS)")
        print("5. Web Application Scan Only")
        
        scan_type = input("\nSelect scan type (default: 2): ").strip() or "2"
    else:
        scan_type = "oscp"  # Special OSCP mode
    
    # Select scan speed
    print("\n=== Scan Speed Selection ===")
    print("Available speeds:")
    for speed_name, speed_config in SCAN_SPEEDS.items():
        print(f"  {speed_name}: {speed_config['description']}")
    
    scan_speed = input("\nSelect scan speed (default: normal): ").strip().lower() or "normal"
    
    if scan_speed not in SCAN_SPEEDS:
        print(f"Invalid speed '{scan_speed}', using 'normal'")
        scan_speed = "normal"
    
    print(f"[+] Using '{scan_speed}' scan speed")
    logging.info(f"Scan speed: {scan_speed}, Scan mode: {'OSCP' if oscp_mode else 'Full'}, Scan type: {scan_type}")
    
    # Network discovery
    network_range = input("\nEnter network range (default 192.168.1.0/24): ").strip() or "192.168.1.0/24"
    
    if not validate_network(network_range):
        print("Invalid network range")
        logging.error(f"Invalid network range: {network_range}")
        return
    
    print(f"\n[*] Starting discovery on {network_range}")
    logging.info(f"Starting discovery on {network_range}")
    active_devices = discovery(network_range)
    print(f"[+] Found {len(active_devices)} active devices")
    logging.info(f"Found {len(active_devices)} active devices: {active_devices}")
    
    results = {
        "authorization": auth_ref, 
        "scan_time": str(datetime.now()), 
        "scan_speed": scan_speed,
        "scan_mode": "OSCP-Compliant" if oscp_mode else "Full Security Scan",
        "scan_type": scan_type,
        "devices": []
    }
    
    # OSCP MODE - Use oscp_compliant_scan for each device
    if oscp_mode:
        for device in active_devices:
            device_results = oscp_compliant_scan(device, speed=scan_speed)
            results["devices"].append(device_results)
        
        # OSCP Web Enumeration
        url = input("\nEnter URL for OSCP-compliant web enumeration (or press Enter to skip): ").strip()
        if url:
            url = validate_url(url)
            web_results = oscp_web_enum(url)
            
            # Display results
            print(f"\n[+] Technologies: {', '.join(web_results['technologies']) if web_results['technologies'] else 'None detected'}")
            print(f"[+] Directories found: {len(web_results['directories'])}")
            print(f"[+] Files found: {len(web_results['files'])}")
            
            if web_results['files']:
                print("\n[+] Interesting Files:")
                for file in web_results['files']:
                    print(f"    {file['file']} ({file['size']} bytes)")
            
            if web_results['directories'][:10]:
                print("\n[+] Discovered Directories (first 10):")
                for dir in web_results['directories'][:10]:
                    access = "Accessible" if dir['accessible'] else "Protected"
                    print(f"    {dir['url']} - {access} ({dir['status']})")
            
            results["web_enumeration"] = web_results
    
    # FULL SCAN MODE - Original comprehensive scanning
    else:
        for device in active_devices:
            print(f"\n{'='*60}")
            print(f"[*] Scanning {device}")
            print(f"{'='*60}")
            logging.info(f"Scanning {device}")
            
            device_results = {
                "ip": device,
                "scan_details": {}
            }
            
            # Scan Type 4: Comprehensive Scan
            if scan_type == "4":
                device_results["scan_details"] = comprehensive_scan(device, speed=scan_speed)
            
            # Scan Type 1, 2, 3: Progressive scans
            else:
                # Always do TCP port scan
                print(f"\n[*] TCP Port Scanning...")
                tcp_ports = port_scan(device, range(1, 1025), speed=scan_speed)
                print(f"[+] Open TCP ports: {len(tcp_ports)} - {tcp_ports}")
                device_results["scan_details"]["tcp_ports"] = tcp_ports
                
                # Firewall detection
                device_results["scan_details"]["firewall"] = detect_firewall(device)
                
                # Get MAC address
                mac_info = get_mac_address(device)
                if mac_info:
                    print(f"[+] MAC Address: {mac_info['mac']} ({mac_info['vendor']})")
                    device_results["scan_details"]["mac"] = mac_info
                
                # Scan Type 2+: Service detection
                if scan_type in ["2", "3"]:
                    print(f"\n[*] Service Detection and OS Fingerprinting...")
                    services, os_info = full_scan(device)
                    device_results["scan_details"]["services"] = services
                    device_results["scan_details"]["os"] = os_info
                    
                    print(f"[+] OS: {os_info if os_info else 'Unknown'}")
                    for service in services[:10]:
                        print(f"    Port: {service['port']}, Service: {service['service']}, Version: {service.get('version', 'N/A')}")
                
                # Scan Type 3: Full scan with UDP and banners
                if scan_type == "3":
                    print(f"\n[*] UDP Port Scanning...")
                    udp_ports = udp_port_scan(device, speed=scan_speed)
                    print(f"[+] Open UDP ports: {len(udp_ports)} - {udp_ports}")
                    device_results["scan_details"]["udp_ports"] = udp_ports
                    
                    print(f"\n[*] Banner Grabbing...")
                    banners = []
                    for port in tcp_ports[:15]:
                        banner = banner_grab(device, port)
                        if banner:
                            banners.append(banner)
                            print(f"[+] Port {port}: {banner['service']}")
                            if banner.get('banner'):
                                print(f"    Banner: {banner['banner'][:80]}")
                    device_results["scan_details"]["banners"] = banners
                    
                    # SMB enumeration if SMB ports open
                    if 445 in tcp_ports or 139 in tcp_ports:
                        print(f"\n[*] SMB Enumeration...")
                        smb_info = smb_enumeration(device)
                        if smb_info.get("netbios_name"):
                            print(f"[+] NetBIOS Name: {smb_info['netbios_name']}")
                            print(f"[+] Workgroup: {smb_info.get('workgroup', 'Unknown')}")
                            if smb_info.get('shares'):
                                print(f"[+] Shares: {', '.join(smb_info['shares'])}")
                        device_results["scan_details"]["smb"] = smb_info
                    
                    # SSL/TLS scan if HTTPS port open
                    if 443 in tcp_ports:
                        print(f"\n[*] SSL/TLS Security Scan...")
                        try:
                            hostname = socket.gethostbyaddr(device)[0]
                            ssl_results = ssl_tls_scan(hostname)
                            if ssl_results.get("certificate"):
                                cert = ssl_results["certificate"]
                                print(f"[+] Certificate Subject: {cert.get('subject', {}).get('commonName', 'N/A')}")
                                print(f"[+] Certificate Issuer: {cert.get('issuer', {}).get('commonName', 'N/A')}")
                                print(f"[+] Valid Until: {cert.get('notAfter', 'N/A')}")
                            if ssl_results.get("vulnerabilities"):
                                print(f"[!] SSL/TLS Vulnerabilities Found:")
                                for vuln in ssl_results["vulnerabilities"]:
                                    print(f"    [{vuln['severity']}] {vuln['type']}")
                            device_results["scan_details"]["ssl_tls"] = ssl_results
                        except Exception as e:
                            print(f"[!] Could not perform SSL scan: {e}")
            
            results["devices"].append(device_results)
        
        # DNS Enumeration (optional for full mode)
        dns_domain = input("\nEnter domain for DNS enumeration (or press Enter to skip): ").strip()
        if dns_domain:
            print(f"\n[*] DNS Enumeration for {dns_domain}")
            try:
                dns_results = dns_enumeration(dns_domain)
                print(f"\n[+] DNS Records:")
                for record_type, records in dns_results.items():
                    if records and record_type != "domain" and record_type != "subdomains":
                        print(f"  {record_type}: {records}")
                if dns_results.get("subdomains"):
                    print(f"\n[+] Discovered Subdomains ({len(dns_results['subdomains'])}):")
                    for subdomain in dns_results["subdomains"][:20]:
                        print(f"    {subdomain['subdomain']}: {', '.join(subdomain['ip'])}")
                results["dns_enumeration"] = dns_results
            except Exception as e:
                print(f"[!] DNS enumeration failed: {e}")
        
        # Web vulnerability scan (FULL MODE ONLY)
        url = input("\nEnter URL for web vulnerability scan (or press Enter to skip): ").strip()
        if url or scan_type == "5":
            if not url:
                url = input("Enter URL for web application scan: ").strip()
            
            if url:
                url = validate_url(url)
                print(f"\n{'='*60}")
                print(f"[*] Web Application Security Scan: {url}")
                print(f"{'='*60}")
                
                vuln_results = enhanced_vuln_scan(url, scan_speed=scan_speed)
                
                # Display results
                print("\n=== Web Vulnerability Scan Results ===")
                
                if vuln_results.get("technologies"):
                    print(f"\n[+] Technologies Detected:")
                    for tech in vuln_results["technologies"]:
                        print(f"    {tech}")
                
                if vuln_results.get("exposed_paths"):
                    print(f"\n[!] Exposed Paths ({len(vuln_results['exposed_paths'])}):")
                    for path in vuln_results["exposed_paths"][:20]:
                        severity_marker = "[CRITICAL]" if path['severity'] == "CRITICAL" else "[MEDIUM]"
                        print(f"  {severity_marker} {path['url']} - Status: {path['status']}")
                        if "content_findings" in path:
                            for finding in path["content_findings"]:
                                print(f"      |-- {finding['type']} ({finding['severity']})")
                
                if vuln_results.get("subdirectories"):
                    print(f"\n[+] Discovered Directories ({len(vuln_results['subdirectories'])}):")
                    for dir in vuln_results["subdirectories"][:15]:
                        access = "Accessible" if dir['accessible'] else "Protected"
                        print(f"    {dir['url']} - {access} ({dir['status']})")
                
                if vuln_results.get("sql_injection"):
                    print(f"\n[!] SQL Injection Vulnerabilities:")
                    for vuln in vuln_results["sql_injection"]:
                        print(f"  [CRITICAL] {vuln['type']} - Payload: {vuln['payload']}")
                
                if vuln_results.get("xss"):
                    print(f"\n[!] XSS Vulnerabilities:")
                    for vuln in vuln_results["xss"]:
                        print(f"  [HIGH] {vuln['type']} - Payload: {vuln['payload']}")
                
                if vuln_results.get("auth_bypass"):
                    print(f"\n[!] Authentication Testing:")
                    for vuln in vuln_results["auth_bypass"]:
                        if vuln["type"] == "Authentication Testing Skipped":
                            print(f"  [INFO] {vuln['type']} - {vuln['reason']}")
                        else:
                            print(f"  [CRITICAL] {vuln['type']} - {vuln['username']}:{vuln['password']}")
                
                results["web_vulnerabilities"] = vuln_results
    
    # Generate summary
    print(f"\n{'='*60}")
    print("SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"Scan Mode: {results['scan_mode']}")
    print(f"Total hosts scanned: {len(active_devices)}")
    
    if oscp_mode:
        # OSCP mode summary
        total_tcp = sum(len(d.get("tcp_ports", [])) for d in results["devices"])
        total_udp = sum(len(d.get("udp_ports", [])) for d in results["devices"])
        print(f"Total open TCP ports: {total_tcp}")
        if total_udp > 0:
            print(f"Total open UDP ports: {total_udp}")
        print("\n[!] OSCP MODE: No automated vulnerability testing performed")
        print("[!] All findings require manual verification and exploitation")
    else:
        # Full mode summary
        total_tcp = sum(len(d["scan_details"].get("tcp_ports", [])) for d in results["devices"])
        total_udp = sum(len(d["scan_details"].get("udp_ports", [])) for d in results["devices"])
        print(f"Total open TCP ports: {total_tcp}")
        if total_udp > 0:
            print(f"Total open UDP ports: {total_udp}")
        
        # Count vulnerabilities
        if results.get("web_vulnerabilities"):
            web_vuln = results["web_vulnerabilities"]
            vuln_count = (
                len(web_vuln.get("sql_injection", [])) +
                len(web_vuln.get("xss", [])) +
                len([a for a in web_vuln.get("auth_bypass", []) if a["type"] != "Authentication Testing Skipped"])
            )
            if vuln_count > 0:
                print(f"\n[!] Total web vulnerabilities found: {vuln_count}")
    
    # Save results
    reporting_to_file(results)
    print("\n[+] Scan complete")
    print(f"[+] Detailed results saved to scan_results.json")
    logging.info("Scan complete")

if __name__ == "__main__":
    main()