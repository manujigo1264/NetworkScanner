# 🔒 Network Security Scanner

![Python](https://img.shields.io/badge/python-3.7%2B-blue?style=flat-square)
![OSCP](https://img.shields.io/badge/OSCP-Compliant-orange?style=flat-square)
![License](https://img.shields.io/badge/license-Educational-green?style=flat-square)

Professional network security scanner with **OSCP-compliant mode** for exam use and full vulnerability assessment mode for real-world testing.

## ✨ Features

### Network Scanning
- TCP/UDP port scanning (multi-threaded)
- Service version detection & OS fingerprinting
- Banner grabbing & MAC address discovery
- DNS/SMB enumeration & SSL/TLS analysis

### Web Application Testing (Full Mode Only)
- SQL injection & XSS detection
- Directory enumeration & tech detection
- Authentication testing with lockout detection
- Sensitive data exposure analysis

### Dual Operating Modes

**🎓 OSCP-Compliant Mode**
- Enumeration only (no automated exploitation)
- Exam-safe: port scanning, service detection, banner grabbing
- Perfect for OSCP exam preparation

**🔥 Full Security Mode**
- Complete vulnerability assessment
- Automated SQLi/XSS testing
- Credential testing & content analysis

## 🚀 Quick Start

### Installation
```bash
# Install Nmap first
# Windows: https://nmap.org/download.html
# Linux: sudo apt-get install nmap
# macOS: brew install nmap

# Clone and setup
git clone https://github.com/manujigo1264/NetworkScanner.git
cd NetworkScanner
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install python-nmap requests
Basic Usage
bash# Run with admin/root privileges
sudo python NetworkScanner.py

# Select mode
1. Full Security Scan (includes automated vulnerability testing)
2. OSCP-Compliant Scan (enumeration only)

# Choose speed: stealth | slow | normal | fast | aggressive
# Enter target: 192.168.1.0/24
📊 Scan Modes
FeatureOSCP ModeFull ModePort Scanning✅✅Service Detection✅✅Banner Grabbing✅✅DNS/SMB Enumeration✅✅SQLi/XSS Testing❌✅Credential Testing❌✅Content Analysis❌✅
🎯 OSCP Compliance
Why OSCP Mode?
OSCP exams prohibit automated vulnerability scanners. This tool's OSCP mode:

✅ Performs only enumeration (like nmap, gobuster, enum4linux)
✅ No automated exploitation or vulnerability testing
✅ Explicitly labeled output files (oscp_enum_results.json)
✅ Complies with OffSec exam restrictions

Equivalent to using:
bashnmap -sV -sC -p- target
gobuster dir -u http://target
enum4linux target
After enumeration, YOU manually:

Analyze results
Identify vulnerabilities
Craft exploits
Document methodology

📁 Output Files
FileModeDescriptionscan_results.jsonFullComplete technical resultsscan_results_summary.txtFullHuman-readable summaryoscp_enum_results.jsonOSCPEnumeration data onlyoscp_enum_summary.txtOSCPExam-ready notesnetwork_scanner.logBothAudit trail
⚖️ Legal Notice
⚠️ For authorized testing only. Unauthorized scanning is illegal.
Requirements:

Written authorization from target owner
Defined scope and rules of engagement
Understanding of applicable laws (CFAA, Computer Misuse Act, etc.)

Authorized use cases:

Internal security assessments with approval
Contracted penetration testing
Personal lab environments
Educational/CTF platforms

🔧 Configuration
Scan Speeds:

stealth - 5 workers, 2s timeout (evade IDS)
normal - 50 workers, 0.5s timeout (default)
aggressive - 200 workers, 0.2s timeout (labs/CTF)

Scan Types (Full Mode):

Quick (TCP only) - ~2 min
Standard (TCP + services) - ~5 min
Full (TCP/UDP + banners) - ~15 min
Comprehensive (everything) - ~30 min
Web only - ~10 min

🐛 Troubleshooting
"nmap: command not found"
bash# Install nmap from https://nmap.org
sudo apt-get install nmap  # Linux
brew install nmap          # macOS
"Permission denied"
bash# Run with admin/root privileges
sudo python NetworkScanner.py
No devices found
bash# Test localhost first
Enter network range: 127.0.0.1/32
# Check firewall settings
# Try slower speed
📚 Technical Details
Dependencies:

python-nmap - Nmap Python wrapper
requests - HTTP client
nmap - Network scanning engine (external)

Key Functions:

oscp_compliant_scan() - OSCP enumeration
comprehensive_scan() - Full assessment
enhanced_vuln_scan() - Web vulnerability testing
port_scan() - Multi-threaded port scanning
dns_enumeration() - DNS/subdomain discovery

🤝 Contributing
Contributions welcome! Please:

Fork the repository
Create feature branch (git checkout -b feature/improvement)
Commit changes (git commit -am 'Add feature')
Push to branch (git push origin feature/improvement)
Open Pull Request

📝 License
Educational purposes only. See Legal Notice above.
👨‍💻 Author
Manuj
GitHub: @manujigo1264
🔗 Resources

OSCP Exam Guide
Nmap Documentation
OWASP Testing Guide