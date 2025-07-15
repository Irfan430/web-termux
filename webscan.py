#!/usr/bin/env python3
"""
IRFAN AHMMED PERSONAL CYBERSEC TOOL
===================================
Single-file cybersecurity toolkit for Termux/Linux/macOS
Author: Irfan Ahmmed
"""

import os
import sys
import subprocess
import platform
import logging
import json
import time
import random
import string
import socket
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('webscan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ToolkitInstaller:
    """Handles automatic installation of dependencies"""
    
    def __init__(self):
        self.is_termux = 'com.termux' in os.environ.get('PREFIX', '')
        self.system = platform.system().lower()
        
    def check_python_packages(self):
        """Check and install required Python packages"""
        required_packages = [
            'requests', 'pandas', 'scikit-learn', 'matplotlib', 
            'joblib', 'paramiko', 'fpdf2', 'typer', 'rich'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
                logger.info(f"✓ {package} is already installed")
            except ImportError:
                missing_packages.append(package)
                logger.warning(f"✗ {package} is missing")
        
        if missing_packages:
            logger.info("Installing missing Python packages...")
            for package in missing_packages:
                try:
                    subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                                 check=True, capture_output=True)
                    logger.info(f"✓ Successfully installed {package}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"✗ Failed to install {package}: {e}")
                    
    def check_system_tools(self):
        """Check and install required system tools"""
        tools = ['nmap', 'nikto']
        
        for tool in tools:
            if not self._is_tool_installed(tool):
                logger.warning(f"✗ {tool} is not installed")
                self._install_tool(tool)
            else:
                logger.info(f"✓ {tool} is already installed")
                
    def _is_tool_installed(self, tool):
        """Check if a system tool is installed"""
        try:
            subprocess.run(['which', tool], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
            
    def _install_tool(self, tool):
        """Install system tool based on platform"""
        try:
            if self.is_termux:
                subprocess.run(['pkg', 'install', '-y', tool], check=True)
            elif self.system == 'linux':
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                subprocess.run(['sudo', 'apt', 'install', '-y', tool], check=True)
            elif self.system == 'darwin':  # macOS
                subprocess.run(['brew', 'install', tool], check=True)
            
            logger.info(f"✓ Successfully installed {tool}")
        except subprocess.CalledProcessError as e:
            logger.error(f"✗ Failed to install {tool}: {e}")
            logger.error("Please install manually or run with sudo privileges")

class VulnerabilityScanner:
    """Handles vulnerability scanning with Nmap and Nikto"""
    
    def __init__(self, target):
        self.target = target
        self.results = {}
        
    def nmap_scan(self):
        """Perform Nmap scan"""
        logger.info(f"Starting Nmap scan on {self.target}")
        try:
            # Basic port scan
            cmd = ['nmap', '-sV', '-sC', '-O', '--script=vuln', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            self.results['nmap'] = {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info("Nmap scan completed")
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out")
            return "Nmap scan timed out"
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return f"Nmap scan failed: {e}"
            
    def nikto_scan(self):
        """Perform Nikto web vulnerability scan"""
        logger.info(f"Starting Nikto scan on {self.target}")
        try:
            cmd = ['nikto', '-h', self.target, '-Format', 'txt']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            self.results['nikto'] = {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info("Nikto scan completed")
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.error("Nikto scan timed out")
            return "Nikto scan timed out"
        except Exception as e:
            logger.error(f"Nikto scan failed: {e}")
            return f"Nikto scan failed: {e}"
            
    def run_full_scan(self):
        """Run both Nmap and Nikto scans"""
        nmap_result = self.nmap_scan()
        nikto_result = self.nikto_scan()
        
        return {
            'nmap': nmap_result,
            'nikto': nikto_result,
            'metadata': self.results
        }

class BruteForceSimulator:
    """Simulates brute force attacks for testing purposes"""
    
    def __init__(self, target):
        self.target = target
        # Common credentials for testing (educational purposes only)
        self.common_passwords = [
            'admin', 'password', '123456', 'root', 'toor', 'pass',
            'administrator', 'guest', 'user', 'test', 'demo'
        ]
        self.common_usernames = [
            'admin', 'root', 'user', 'test', 'guest', 'administrator',
            'demo', 'ftp', 'anonymous', 'www-data'
        ]
        
    def ssh_brute_force(self, port=22):
        """Simulate SSH brute force (for testing only)"""
        logger.info(f"Starting SSH brute force simulation on {self.target}:{port}")
        results = []
        
        try:
            import paramiko
            
            for username in self.common_usernames[:5]:  # Limit attempts
                for password in self.common_passwords[:5]:
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(self.target, port=port, username=username, 
                                  password=password, timeout=5)
                        
                        result = f"SUCCESS: {username}:{password}"
                        results.append(result)
                        logger.warning(result)
                        ssh.close()
                        break
                        
                    except paramiko.AuthenticationException:
                        result = f"FAILED: {username}:{password}"
                        results.append(result)
                        
                    except Exception as e:
                        result = f"ERROR: {username}:{password} - {str(e)}"
                        results.append(result)
                        
                    time.sleep(1)  # Be respectful
                    
        except ImportError:
            logger.error("Paramiko not available for SSH testing")
            results.append("Paramiko not available for SSH testing")
            
        return results
        
    def ftp_brute_force(self, port=21):
        """Simulate FTP brute force (for testing only)"""
        logger.info(f"Starting FTP brute force simulation on {self.target}:{port}")
        results = []
        
        try:
            import ftplib
            
            for username in self.common_usernames[:5]:
                for password in self.common_passwords[:5]:
                    try:
                        ftp = ftplib.FTP()
                        ftp.connect(self.target, port, timeout=5)
                        ftp.login(username, password)
                        
                        result = f"SUCCESS: {username}:{password}"
                        results.append(result)
                        logger.warning(result)
                        ftp.quit()
                        break
                        
                    except ftplib.error_perm:
                        result = f"FAILED: {username}:{password}"
                        results.append(result)
                        
                    except Exception as e:
                        result = f"ERROR: {username}:{password} - {str(e)}"
                        results.append(result)
                        
                    time.sleep(1)
                    
        except ImportError:
            logger.error("ftplib not available for FTP testing")
            results.append("ftplib not available for FTP testing")
            
        return results
        
    def http_brute_force(self, port=80):
        """Simulate HTTP basic auth brute force"""
        logger.info(f"Starting HTTP brute force simulation on {self.target}:{port}")
        results = []
        
        try:
            import requests
            
            for username in self.common_usernames[:5]:
                for password in self.common_passwords[:5]:
                    try:
                        url = f"http://{self.target}:{port}"
                        response = requests.get(url, auth=(username, password), timeout=5)
                        
                        if response.status_code == 200:
                            result = f"SUCCESS: {username}:{password}"
                            results.append(result)
                            logger.warning(result)
                            break
                        else:
                            result = f"FAILED: {username}:{password} - Status: {response.status_code}"
                            results.append(result)
                            
                    except Exception as e:
                        result = f"ERROR: {username}:{password} - {str(e)}"
                        results.append(result)
                        
                    time.sleep(1)
                    
        except ImportError:
            logger.error("requests not available for HTTP testing")
            results.append("requests not available for HTTP testing")
            
        return results

class PhishingSimulator:
    """Simulates phishing emails for security awareness training"""
    
    def __init__(self):
        # Hardcoded SMTP configuration for personal use
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = "your_email@gmail.com"  # Replace with your email
        self.sender_password = "your_app_password"  # Replace with app password
        
    def send_phishing_test(self, target_email, template="basic"):
        """Send a phishing simulation email"""
        logger.info(f"Sending phishing simulation to {target_email}")
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            templates = {
                "basic": {
                    "subject": "Urgent: Account Verification Required",
                    "body": """
                    Dear User,
                    
                    This is a security awareness test. Your account requires immediate verification.
                    
                    ** THIS IS A PHISHING SIMULATION FOR TRAINING PURPOSES **
                    
                    If this was a real phishing email, you would have been asked to click a malicious link.
                    
                    Stay vigilant!
                    - Security Team
                    """
                },
                "urgent": {
                    "subject": "Action Required: Account Suspended",
                    "body": """
                    URGENT: Your account has been temporarily suspended.
                    
                    ** THIS IS A PHISHING SIMULATION FOR TRAINING PURPOSES **
                    
                    Remember to always verify the sender before clicking links or providing credentials.
                    
                    - Security Awareness Team
                    """
                }
            }
            
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = target_email
            msg['Subject'] = templates[template]['subject']
            
            msg.attach(MIMEText(templates[template]['body'], 'plain'))
            
            # Note: This is a simulation - actual sending would require valid credentials
            logger.info("Phishing simulation email prepared (not actually sent without valid SMTP config)")
            
            return f"Phishing simulation prepared for {target_email}"
            
        except ImportError:
            logger.error("smtplib not available for email simulation")
            return "Email libraries not available"
        except Exception as e:
            logger.error(f"Phishing simulation failed: {e}")
            return f"Simulation failed: {e}"

class AIRiskPredictor:
    """AI-based risk prediction using machine learning"""
    
    def __init__(self):
        self.model = None
        self.model_file = "security_model.pkl"
        
    def create_dummy_model(self):
        """Create a dummy ML model for demonstration"""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.datasets import make_classification
            import joblib
            
            # Generate dummy training data
            X, y = make_classification(n_samples=1000, n_features=10, 
                                     n_classes=3, random_state=42)
            
            # Train a simple model
            model = RandomForestClassifier(n_estimators=100, random_state=42)
            model.fit(X, y)
            
            # Save the model
            joblib.dump(model, self.model_file)
            logger.info("Dummy AI model created and saved")
            return model
            
        except ImportError:
            logger.error("sklearn not available for AI prediction")
            return None
            
    def load_model(self):
        """Load existing model or create new one"""
        try:
            import joblib
            
            if os.path.exists(self.model_file):
                self.model = joblib.load(self.model_file)
                logger.info("AI model loaded successfully")
            else:
                logger.info("No existing model found, creating new one...")
                self.model = self.create_dummy_model()
                
            return self.model is not None
            
        except ImportError:
            logger.error("joblib not available for model loading")
            return False
            
    def predict_risk(self, target):
        """Predict security risk for target"""
        if not self.load_model():
            return "AI model not available"
            
        try:
            import numpy as np
            
            # Create dummy features based on target characteristics
            features = self._extract_features(target)
            
            if self.model:
                prediction = self.model.predict([features])[0]
                probability = self.model.predict_proba([features])[0]
                
                risk_levels = ['Low Risk', 'Medium Risk', 'High Risk']
                risk_level = risk_levels[prediction]
                confidence = max(probability) * 100
                
                result = {
                    'target': target,
                    'risk_level': risk_level,
                    'confidence': f"{confidence:.2f}%",
                    'features': features,
                    'timestamp': datetime.now().isoformat()
                }
                
                logger.info(f"Risk prediction completed: {risk_level}")
                return result
            else:
                return "Model not available"
                
        except Exception as e:
            logger.error(f"Risk prediction failed: {e}")
            return f"Prediction failed: {e}"
            
    def _extract_features(self, target):
        """Extract features for ML prediction (dummy implementation)"""
        # Simple feature extraction based on target characteristics
        features = [
            len(target),  # Length of target
            target.count('.'),  # Number of dots (domain structure)
            1 if target.isdigit() else 0,  # Is IP address
            len(target.split('.')),  # Number of segments
            random.uniform(0, 1),  # Random feature 1
            random.uniform(0, 1),  # Random feature 2
            random.uniform(0, 1),  # Random feature 3
            random.uniform(0, 1),  # Random feature 4
            random.uniform(0, 1),  # Random feature 5
            random.uniform(0, 1),  # Random feature 6
        ]
        return features

class ReportGenerator:
    """Generates PDF reports using fpdf2"""
    
    def __init__(self):
        self.report_data = {}
        
    def add_scan_data(self, scan_type, data):
        """Add scan data to report"""
        self.report_data[scan_type] = data
        
    def generate_pdf_report(self, target, output_file="security_report.pdf"):
        """Generate comprehensive PDF report"""
        try:
            from fpdf import FPDF
            
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            
            # Title
            pdf.cell(0, 10, 'CYBERSECURITY ASSESSMENT REPORT', 0, 1, 'C')
            pdf.ln(10)
            
            # Target information
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, f'Target: {target}', 0, 1)
            pdf.cell(0, 10, f'Report Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
            pdf.ln(10)
            
            # Add sections for each scan type
            for scan_type, data in self.report_data.items():
                pdf.set_font('Arial', 'B', 14)
                pdf.cell(0, 10, f'{scan_type.upper()} RESULTS', 0, 1)
                pdf.ln(5)
                
                pdf.set_font('Arial', '', 10)
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        pdf.multi_cell(0, 5, f'{key}: {str(value)[:100]}...')
                elif isinstance(data, list):
                    for item in data[:10]:  # Limit items
                        pdf.multi_cell(0, 5, f'• {str(item)[:100]}...')
                else:
                    pdf.multi_cell(0, 5, str(data)[:500] + '...')
                
                pdf.ln(10)
            
            # Save report
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            
            report_path = reports_dir / output_file
            pdf.output(str(report_path))
            
            logger.info(f"PDF report generated: {report_path}")
            return str(report_path)
            
        except ImportError:
            logger.error("fpdf2 not available for PDF generation")
            return "PDF generation not available"
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return f"PDF generation failed: {e}"

class CyberSecurityToolkit:
    """Main toolkit class"""
    
    def __init__(self):
        self.installer = ToolkitInstaller()
        self.report_generator = ReportGenerator()
        
    def show_banner(self):
        """Display toolkit banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║              IRFAN AHMMED PERSONAL CYBERSEC TOOL             ║
║                                                              ║
║  Single-file toolkit for Termux/Linux/macOS                 ║
║  Educational purposes only - Use responsibly                 ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def show_menu(self):
        """Display main menu"""
        menu = """
=== IRFAN AHMMED PERSONAL CYBERSEC TOOL ===

[1] Vulnerability Scan (Nmap + Nikto)
[2] Brute Force Simulation (SSH/FTP/HTTP)
[3] Phishing Simulation (SMTP - hardcoded sender config inside the script)
[4] AI Risk Prediction (loads sklearn model.pkl)
[5] Generate PDF Report (fpdf2)
[6] Exit

Enter your choice (1-6): """
        
        return input(menu).strip()
        
    def get_target(self):
        """Get target from user"""
        return input("Enter target domain/IP: ").strip()
        
    def vulnerability_scan(self, target):
        """Perform vulnerability scanning"""
        print(f"\n🔍 Starting vulnerability scan on {target}...")
        scanner = VulnerabilityScanner(target)
        results = scanner.run_full_scan()
        
        # Save results
        self.save_results('vulnerability_scan', results, target)
        self.report_generator.add_scan_data('vulnerability_scan', results)
        
        print("\n✅ Vulnerability scan completed!")
        print(f"Results saved to reports/vulnerability_scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
    def brute_force_simulation(self, target):
        """Perform brute force simulation"""
        print(f"\n💥 Starting brute force simulation on {target}...")
        print("⚠️  This is for educational/testing purposes only!")
        
        simulator = BruteForceSimulator(target)
        
        print("\n📍 Testing SSH...")
        ssh_results = simulator.ssh_brute_force()
        
        print("\n📍 Testing FTP...")
        ftp_results = simulator.ftp_brute_force()
        
        print("\n📍 Testing HTTP...")
        http_results = simulator.http_brute_force()
        
        results = {
            'ssh': ssh_results,
            'ftp': ftp_results,
            'http': http_results
        }
        
        # Save results
        self.save_results('brute_force', results, target)
        self.report_generator.add_scan_data('brute_force', results)
        
        print("\n✅ Brute force simulation completed!")
        
    def phishing_simulation(self):
        """Perform phishing simulation"""
        print("\n📧 Phishing Simulation")
        print("⚠️  For security awareness training only!")
        
        target_email = input("Enter target email for simulation: ").strip()
        template = input("Choose template (basic/urgent) [basic]: ").strip() or "basic"
        
        simulator = PhishingSimulator()
        result = simulator.send_phishing_test(target_email, template)
        
        # Save results
        self.save_results('phishing_simulation', {'result': result, 'target': target_email}, target_email)
        self.report_generator.add_scan_data('phishing_simulation', result)
        
        print(f"\n✅ {result}")
        
    def ai_risk_prediction(self, target):
        """Perform AI risk prediction"""
        print(f"\n🤖 AI Risk Prediction for {target}...")
        
        predictor = AIRiskPredictor()
        result = predictor.predict_risk(target)
        
        # Save results
        self.save_results('ai_risk_prediction', result, target)
        self.report_generator.add_scan_data('ai_risk_prediction', result)
        
        print("\n✅ AI Risk Prediction completed!")
        if isinstance(result, dict):
            print(f"Risk Level: {result['risk_level']}")
            print(f"Confidence: {result['confidence']}")
        
    def generate_report(self):
        """Generate comprehensive PDF report"""
        print("\n📄 Generating PDF Report...")
        
        if not self.report_generator.report_data:
            print("❌ No scan data available for report generation.")
            print("Please run some scans first.")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"security_report_{timestamp}.pdf"
        
        result = self.report_generator.generate_pdf_report("Multiple Targets", output_file)
        print(f"\n✅ Report generated: {result}")
        
    def save_results(self, scan_type, results, target):
        """Save scan results to JSON file"""
        try:
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{scan_type}_{target}_{timestamp}.json"
            filepath = reports_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump({
                    'scan_type': scan_type,
                    'target': target,
                    'timestamp': datetime.now().isoformat(),
                    'results': results
                }, f, indent=2)
                
            logger.info(f"Results saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            
    def run(self):
        """Main toolkit execution loop"""
        try:
            # Show banner
            self.show_banner()
            
            # Check and install dependencies
            print("🔧 Checking dependencies...")
            self.installer.check_python_packages()
            self.installer.check_system_tools()
            print("✅ Dependencies checked!\n")
            
            # Main loop
            while True:
                try:
                    choice = self.show_menu()
                    
                    if choice == '1':
                        target = self.get_target()
                        self.vulnerability_scan(target)
                        
                    elif choice == '2':
                        target = self.get_target()
                        self.brute_force_simulation(target)
                        
                    elif choice == '3':
                        self.phishing_simulation()
                        
                    elif choice == '4':
                        target = self.get_target()
                        self.ai_risk_prediction(target)
                        
                    elif choice == '5':
                        self.generate_report()
                        
                    elif choice == '6':
                        print("\n👋 Thank you for using Irfan Ahmmed's Cybersec Tool!")
                        break
                        
                    else:
                        print("❌ Invalid choice. Please select 1-6.")
                        
                except KeyboardInterrupt:
                    print("\n\n⚠️  Operation interrupted by user.")
                    continue
                except Exception as e:
                    logger.error(f"Error in menu operation: {e}")
                    print(f"❌ An error occurred: {e}")
                    continue
                    
                input("\nPress Enter to continue...")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
        except Exception as e:
            logger.error(f"Critical error: {e}")
            print(f"❌ Critical error: {e}")

def main():
    """Main entry point"""
    try:
        toolkit = CyberSecurityToolkit()
        toolkit.run()
    except Exception as e:
        print(f"❌ Failed to start toolkit: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()