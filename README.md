# 🛡️ Irfan Ahmmed Personal Cybersecurity Toolkit

A complete single-file cybersecurity CLI toolkit written in Python 3, specifically designed for Termux (Android), Linux, and macOS environments. This toolkit provides essential security testing and assessment capabilities in a lightweight, portable format.

## 🚀 Features

- **Single-file deployment** - Everything contained in `webscan.py`
- **Automatic dependency management** - Auto-installs missing Python packages and system tools
- **Cross-platform compatibility** - Works on Termux, Linux, and macOS
- **Comprehensive security testing** - Multiple security assessment tools in one package
- **Professional reporting** - Generates detailed PDF reports and JSON logs
- **Educational focus** - Designed for learning and authorized testing only

## 📋 Capabilities

### 1. 🔍 Vulnerability Scanning
- **Nmap integration** - Port scanning, service detection, OS fingerprinting
- **Nikto web scanning** - Web application vulnerability assessment
- **Comprehensive reporting** - Detailed scan results with timestamps

### 2. 💥 Brute Force Simulation
- **SSH testing** - Password attack simulation on SSH services
- **FTP testing** - FTP credential brute force simulation
- **HTTP testing** - Basic authentication brute force testing
- **Educational purpose** - Limited attempts with respectful timing

### 3. 📧 Phishing Simulation
- **Email template generation** - Pre-built phishing awareness templates
- **SMTP configuration** - Hardcoded settings for quick deployment
- **Security awareness** - Training-focused phishing simulations

### 4. 🤖 AI Risk Prediction
- **Machine learning model** - Automated risk assessment using scikit-learn
- **Feature extraction** - Target characteristic analysis
- **Risk scoring** - Confidence-based risk level prediction

### 5. 📄 PDF Report Generation
- **Professional reports** - Comprehensive security assessment documentation
- **Multiple formats** - JSON logs and PDF reports
- **Timestamped results** - Detailed audit trails

## 🛠️ Installation & Setup

### Quick Start
```bash
# Clone the repository
git clone https://github.com/Irfan430/webscan.git
cd webscan

# Run the toolkit (auto-installs dependencies)
python webscan.py
```

### Manual Installation
If you prefer to install dependencies manually:

#### Python Packages
```bash
pip install requests pandas scikit-learn matplotlib joblib paramiko fpdf2 typer rich
```

#### System Tools

**Termux (Android):**
```bash
pkg install nmap nikto
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap nikto
```

**macOS:**
```bash
brew install nmap nikto
```

## 📱 Usage

### Interactive Menu
When you run `python webscan.py`, you'll see:

```
╔══════════════════════════════════════════════════════════════╗
║              IRFAN AHMMED PERSONAL CYBERSEC TOOL             ║
║                                                              ║
║  Single-file toolkit for Termux/Linux/macOS                 ║
║  Educational purposes only - Use responsibly                 ║
╚══════════════════════════════════════════════════════════════╝

=== IRFAN AHMMED PERSONAL CYBERSEC TOOL ===

[1] Vulnerability Scan (Nmap + Nikto)
[2] Brute Force Simulation (SSH/FTP/HTTP)
[3] Phishing Simulation (SMTP - hardcoded sender config inside the script)
[4] AI Risk Prediction (loads sklearn model.pkl)
[5] Generate PDF Report (fpdf2)
[6] Exit

Enter your choice (1-6):
```

### Example Workflow
1. **Run vulnerability scan** on target domain/IP
2. **Perform brute force testing** (authorized targets only)
3. **Generate AI risk assessment** 
4. **Create comprehensive PDF report**
5. **Review logs** in `webscan.log`

### Output Structure
```
webscan/
├── webscan.py              # Main toolkit
├── README.md              # This file
├── webscan.log            # Execution logs
├── security_model.pkl     # AI model (auto-generated)
└── reports/               # Generated reports
    ├── vulnerability_scan_target_timestamp.json
    ├── brute_force_target_timestamp.json
    ├── ai_risk_prediction_target_timestamp.json
    └── security_report_timestamp.pdf
```

## ⚙️ Configuration

### SMTP Settings (Phishing Simulation)
Edit the hardcoded values in `PhishingSimulator` class:
```python
self.smtp_server = "smtp.gmail.com"
self.smtp_port = 587
self.sender_email = "your_email@gmail.com"
self.sender_password = "your_app_password"
```

### Scan Customization
Modify scan parameters in the respective classes:
- Timeout values
- Wordlists for brute force
- Nmap scan options
- AI model features

## 🔒 Security & Ethics

### ⚠️ Important Disclaimers
- **Educational purposes only** - This tool is designed for learning and authorized testing
- **Authorized use only** - Only test systems you own or have explicit permission to test
- **No malicious intent** - This toolkit is for defensive security and awareness training
- **Respect rate limits** - Built-in delays prevent aggressive scanning
- **Legal compliance** - Ensure all usage complies with local laws and regulations

### 🛡️ Responsible Usage
- Always obtain proper authorization before testing
- Use minimal necessary force for assessments
- Document all testing activities
- Report findings responsibly
- Respect privacy and confidentiality

## 🔧 Troubleshooting

### Common Issues

**Permission Denied (Linux/macOS):**
```bash
sudo python webscan.py
```

**Missing Tools (Manual Install):**
```bash
# Termux
pkg install python nmap nikto

# Ubuntu/Debian
sudo apt install python3 nmap nikto

# macOS
brew install python nmap nikto
```

**Python Package Issues:**
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Platform-Specific Notes

**Termux (Android):**
- No root required for most functions
- Some system tools may have limited functionality
- Storage permissions may be needed for report generation

**Linux:**
- Sudo may be required for system tool installation
- Nmap requires root for some advanced features
- Check firewall settings if network issues occur

**macOS:**
- Homebrew required for tool installation
- System Integrity Protection may limit some features
- Network security settings may affect scanning

## 📝 Logging

All activities are logged to `webscan.log` with timestamps:
- Scan initiation and completion
- Dependency checks and installations
- Error messages and debugging information
- User interactions and choices

## 🤝 Contributing

This is a personal toolkit, but suggestions are welcome:
1. Open an issue for bugs or feature requests
2. Ensure all contributions maintain educational focus
3. Test across multiple platforms before submitting
4. Update documentation for new features

## 📄 License

This project is licensed under the terms included in the LICENSE file.

## 📞 Support

For issues, questions, or educational inquiries:
- Create an issue in this repository
- Ensure you include platform details and error logs
- Check existing issues before creating new ones

## 🙏 Acknowledgments

- **Nmap Project** - Network scanning capabilities
- **Nikto** - Web vulnerability scanning
- **Scikit-learn** - Machine learning framework
- **FPDF** - PDF generation library
- **Paramiko** - SSH client functionality

---

**Remember: Use this tool responsibly and only on systems you own or have explicit permission to test.**