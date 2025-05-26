#!/usr/bin/env python3
"""
Advanced Report Generator for WinRecon
Analyzes scan output files to provide detailed vulnerability assessment
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

class AdvancedReportGenerator:
    """Advanced report generator that analyzes scan outputs"""
    
    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.vulnerabilities = []
        self.findings = {}
        
    def generate_reports(self, target: Dict, target_dir: Path):
        """Generate comprehensive reports with detailed analysis"""
        try:
            # Analyze all scan outputs
            self.analyze_scan_results(target, target_dir)
            
            # Generate HTML report with findings
            self.generate_html_report(target, target_dir / 'report' / 'report.html')
            
            # Generate JSON report
            self.generate_json_report(target, target_dir / 'report' / 'report.json')
            
            # Generate text summary
            self.generate_text_summary(target, target_dir / 'report' / 'summary.txt')
            
            return True
        except Exception as e:
            self.logger.error(f"Advanced report generation failed: {e}")
            return False
    
    def analyze_scan_results(self, target: Dict, target_dir: Path):
        """Analyze all scan output files for vulnerabilities and findings"""
        self.logger.info("Analyzing scan results for detailed findings...")
        
        # Analyze nmap results
        self.analyze_nmap_outputs(target_dir / 'scans' / 'nmap')
        
        # Analyze SMB enumeration
        self.analyze_smb_outputs(target_dir / 'scans' / 'smb')
        
        # Analyze LDAP enumeration  
        self.analyze_ldap_outputs(target_dir / 'scans' / 'ldap')
        
        # Analyze web enumeration
        self.analyze_web_outputs(target_dir / 'scans' / 'web')
        
        # Check for extracted credentials
        self.analyze_loot(target_dir / 'loot')
        
    def analyze_nmap_outputs(self, nmap_dir: Path):
        """Analyze nmap output files for vulnerabilities"""
        if not nmap_dir.exists():
            return
            
        findings = {
            'os_detection': None,
            'smb_info': {},
            'vulnerabilities': [],
            'services': {}
        }
        
        # Analyze all nmap files
        for nmap_file in nmap_dir.glob('*.nmap'):
            content = self.read_file_safe(nmap_file)
            if not content:
                continue
                
            # Extract OS information
            os_match = re.search(r'Running: (.+)', content)
            if os_match:
                findings['os_detection'] = os_match.group(1)
                
            # Extract SMB version and details
            smb_version = re.search(r'SMB.*Version: ([^\\n]+)', content)
            if smb_version:
                findings['smb_info']['version'] = smb_version.group(1)
                
            # Check for SMB signing
            if 'Message signing enabled but not required' in content:
                self.vulnerabilities.append({
                    'type': 'SMB Signing',
                    'severity': 'Medium',
                    'description': 'SMB signing is not required - relay attacks possible',
                    'recommendation': 'Enable SMB signing requirement'
                })
                
            # Check for SMB vulnerabilities
            if 'ms17-010' in content.lower() or 'eternablue' in content.lower():
                self.vulnerabilities.append({
                    'type': 'EternalBlue (MS17-010)',
                    'severity': 'Critical',
                    'description': 'System vulnerable to EternalBlue exploit',
                    'recommendation': 'Apply MS17-010 security update immediately'
                })
                
            # Check for anonymous SMB access
            if 'allows sessions using username' in content.lower():
                self.vulnerabilities.append({
                    'type': 'Anonymous SMB Access',
                    'severity': 'Medium',
                    'description': 'Anonymous SMB sessions allowed',
                    'recommendation': 'Disable anonymous SMB access'
                })
                
        self.findings['nmap'] = findings
        
    def analyze_smb_outputs(self, smb_dir: Path):
        """Analyze SMB enumeration results"""
        if not smb_dir.exists():
            return
            
        findings = {
            'shares': [],
            'users': [],
            'groups': [],
            'policies': {},
            'null_session': False
        }
        
        for smb_file in smb_dir.glob('*.txt'):
            content = self.read_file_safe(smb_file)
            if not content:
                continue
                
            # Extract share information
            share_pattern = r'Sharename\s+Type\s+Comment\s*\n\s*-+\s*\n(.*?)(?=\n\n|\n[A-Z]|$)'
            share_match = re.search(share_pattern, content, re.DOTALL)
            if share_match:
                shares_text = share_match.group(1)
                for line in shares_text.split('\n'):
                    if line.strip() and not line.startswith('-'):
                        parts = line.split()
                        if len(parts) >= 2:
                            share_name = parts[0]
                            share_type = parts[1]
                            comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                            findings['shares'].append({
                                'name': share_name,
                                'type': share_type,
                                'comment': comment
                            })
                            
            # Check for writable shares
            if 'READ/WRITE' in content or 'WRITE' in content:
                writable_shares = re.findall(r'(\w+).*?WRITE', content)
                for share in writable_shares:
                    if share not in ['IPC$', 'print$']:
                        self.vulnerabilities.append({
                            'type': 'Writable SMB Share',
                            'severity': 'High',
                            'description': f'Share "{share}" allows write access',
                            'recommendation': 'Review and restrict write permissions'
                        })
                        
            # Check for null session
            if 'null session' in content.lower() or 'anonymous' in content.lower():
                findings['null_session'] = True
                self.vulnerabilities.append({
                    'type': 'SMB Null Session',
                    'severity': 'Medium',
                    'description': 'SMB allows null/anonymous sessions',
                    'recommendation': 'Disable null session access'
                })
                
            # Extract user enumeration
            user_pattern = r'user:\[([^\]]+)\]'
            users = re.findall(user_pattern, content)
            findings['users'].extend(users)
            
            # Extract group enumeration
            group_pattern = r'group:\[([^\]]+)\]'
            groups = re.findall(group_pattern, content)
            findings['groups'].extend(groups)
            
        self.findings['smb'] = findings
        
    def analyze_ldap_outputs(self, ldap_dir: Path):
        """Analyze LDAP enumeration results"""
        if not ldap_dir.exists():
            return
            
        findings = {
            'domain_info': {},
            'users': [],
            'groups': [],
            'computers': [],
            'domain_admins': [],
            'kerberoastable': []
        }
        
        for ldap_file in ldap_dir.glob('*.txt'):
            content = self.read_file_safe(ldap_file)
            if not content:
                continue
                
            # Extract domain information
            domain_match = re.search(r'Domain: ([^\n]+)', content)
            if domain_match:
                findings['domain_info']['name'] = domain_match.group(1)
                
            # Extract domain controllers
            dc_pattern = r'DC=([^,\n]+)'
            dcs = re.findall(dc_pattern, content)
            if dcs:
                findings['domain_info']['components'] = dcs
                
            # Check for LDAP anonymous bind
            if 'anonymous bind' in content.lower():
                self.vulnerabilities.append({
                    'type': 'LDAP Anonymous Bind',
                    'severity': 'Low',
                    'description': 'LDAP allows anonymous binds',
                    'recommendation': 'Disable anonymous LDAP binds'
                })
                
            # Extract users with SPNs (Kerberoastable)
            spn_pattern = r'User: ([^\n]+).*?SPN: ([^\n]+)'
            spn_users = re.findall(spn_pattern, content, re.DOTALL)
            for user, spn in spn_users:
                findings['kerberoastable'].append({'user': user, 'spn': spn})
                self.vulnerabilities.append({
                    'type': 'Kerberoastable Account',
                    'severity': 'Medium',
                    'description': f'User "{user}" has SPN and may be Kerberoastable',
                    'recommendation': 'Use strong passwords for service accounts'
                })
                
        self.findings['ldap'] = findings
        
    def analyze_web_outputs(self, web_dir: Path):
        """Analyze web enumeration results"""
        if not web_dir.exists():
            return
            
        findings = {
            'directories': [],
            'files': [],
            'vulnerabilities': [],
            'technologies': []
        }
        
        for web_file in web_dir.glob('*.txt'):
            content = self.read_file_safe(web_file)
            if not content:
                continue
                
            # Extract discovered directories and files
            if 'gobuster' in web_file.name.lower():
                dir_pattern = r'Found: ([^\s]+)\s+\(Status: (\d+)\)'
                dirs = re.findall(dir_pattern, content)
                findings['directories'].extend([{'path': path, 'status': status} for path, status in dirs])
                
            # Check for common vulnerabilities in Nikto output
            if 'nikto' in web_file.name.lower():
                if 'OSVDB' in content:
                    vulns = re.findall(r'OSVDB-(\d+):\s*([^\n]+)', content)
                    for osvdb_id, desc in vulns:
                        findings['vulnerabilities'].append({
                            'id': f'OSVDB-{osvdb_id}',
                            'description': desc
                        })
                        
        self.findings['web'] = findings
        
    def analyze_loot(self, loot_dir: Path):
        """Analyze extracted credentials and hashes"""
        if not loot_dir.exists():
            return
            
        findings = {
            'credentials': [],
            'hashes': [],
            'tickets': [],
            'secrets': []
        }
        
        # Check credentials directory
        cred_dir = loot_dir / 'credentials'
        if cred_dir.exists():
            for cred_file in cred_dir.glob('*'):
                content = self.read_file_safe(cred_file)
                if not content:
                    continue
                    
                # Count hashes found
                if 'asrep' in cred_file.name.lower():
                    hash_count = len([line for line in content.split('\n') if '$krb5asrep$' in line])
                    if hash_count > 0:
                        findings['hashes'].append(f'ASREPRoast hashes: {hash_count}')
                        self.vulnerabilities.append({
                            'type': 'ASREPRoastable Accounts',
                            'severity': 'High',
                            'description': f'Found {hash_count} ASREPRoastable account(s)',
                            'recommendation': 'Enable Kerberos pre-authentication or use strong passwords'
                        })
                        
                if 'kerberoast' in cred_file.name.lower():
                    hash_count = len([line for line in content.split('\n') if '$krb5tgs$' in line])
                    if hash_count > 0:
                        findings['hashes'].append(f'Kerberoast hashes: {hash_count}')
                        self.vulnerabilities.append({
                            'type': 'Kerberoastable Service Accounts',
                            'severity': 'High',
                            'description': f'Found {hash_count} Kerberoastable service account(s)',
                            'recommendation': 'Use strong passwords for service accounts'
                        })
                        
        self.findings['loot'] = findings
        
    def read_file_safe(self, file_path: Path) -> str:
        """Safely read file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            self.logger.debug(f"Could not read {file_path}: {e}")
            return ""
            
    def generate_html_report(self, target: Dict, output_file: Path):
        """Generate comprehensive HTML report"""
        
        # Calculate risk score
        risk_score = self.calculate_risk_score()
        risk_level = self.get_risk_level(risk_score)
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>WinRecon Advanced Report - {target.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f8f9fa; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header .subtitle {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .content {{ padding: 30px; }}
        .risk-banner {{ text-align: center; padding: 20px; margin: 20px 0; border-radius: 10px; font-weight: bold; font-size: 1.2em; }}
        .risk-critical {{ background: #dc3545; color: white; }}
        .risk-high {{ background: #fd7e14; color: white; }}
        .risk-medium {{ background: #ffc107; color: black; }}
        .risk-low {{ background: #28a745; color: white; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .info-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; }}
        .info-box h3 {{ margin-top: 0; color: #495057; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; display: flex; align-items: center; }}
        .section h2::before {{ content: '🔍'; margin-right: 10px; }}
        .vuln-item {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ffc107; }}
        .vuln-critical {{ background: #f8d7da; border-color: #f5c6cb; border-left-color: #dc3545; }}
        .vuln-high {{ background: #fdecea; border-color: #fdbcb4; border-left-color: #fd7e14; }}
        .vuln-medium {{ background: #fff3cd; border-color: #ffeaa7; border-left-color: #ffc107; }}
        .vuln-low {{ background: #d1ecf1; border-color: #b8daff; border-left-color: #17a2b8; }}
        .vuln-title {{ font-weight: bold; margin-bottom: 5px; }}
        .vuln-desc {{ margin-bottom: 10px; }}
        .vuln-rec {{ font-style: italic; color: #495057; }}
        .port-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; }}
        .port-item {{ background: #e9ecef; padding: 10px; border-radius: 5px; text-align: center; }}
        .port-number {{ font-weight: bold; color: #007bff; font-size: 1.2em; }}
        .share-item {{ background: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 5px; border-left: 3px solid #17a2b8; }}
        .finding-box {{ background: #e8f4f8; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #17a2b8; }}
        .stats {{ display: flex; justify-content: space-around; text-align: center; margin: 20px 0; }}
        .stat-item {{ padding: 15px; background: #f8f9fa; border-radius: 8px; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        .footer {{ margin-top: 40px; padding: 20px; background: #f8f9fa; text-align: center; color: #6c757d; border-top: 1px solid #dee2e6; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ WinRecon Advanced Security Assessment</h1>
            <div class="subtitle">Comprehensive Windows/Active Directory Penetration Test Report</div>
        </div>
        
        <div class="content">
            <div class="risk-banner risk-{risk_level.lower()}">
                Overall Risk Level: {risk_level.upper()} (Score: {risk_score}/100)
            </div>
            
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-number">{len(target.get('open_ports', []))}</div>
                    <div>Open Ports</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{len(self.vulnerabilities)}</div>
                    <div>Vulnerabilities</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{len([v for v in self.vulnerabilities if v['severity'] in ['Critical', 'High']])}</div>
                    <div>High Risk Issues</div>
                </div>
            </div>
            
            <div class="info-grid">
                <div class="info-box">
                    <h3>🎯 Target Information</h3>
                    <p><strong>IP Address:</strong> {target.get('target', 'N/A')}</p>
                    <p><strong>Hostname:</strong> {target.get('hostname', 'N/A') or 'N/A'}</p>
                    <p><strong>Domain:</strong> {target.get('domain', 'N/A') or 'N/A'}</p>
                    <p><strong>Operating System:</strong> {self.findings.get('nmap', {}).get('os_detection', 'Unknown')}</p>
                </div>
                
                <div class="info-box">
                    <h3>📅 Scan Information</h3>
                    <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Scanner:</strong> WinRecon v1.0</p>
                    <p><strong>Credentials Used:</strong> {'Yes' if self.config.get('username') else 'No'}</p>
                    <p><strong>Results Directory:</strong> {target.get('scan_dir', 'N/A')}</p>
                </div>
            </div>
"""

        # Add vulnerabilities section
        if self.vulnerabilities:
            html_content += """
            <div class="section">
                <h2>🚨 Security Vulnerabilities</h2>
"""
            for vuln in sorted(self.vulnerabilities, key=lambda x: {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}.get(x['severity'], 0), reverse=True):
                severity_class = f"vuln-{vuln['severity'].lower()}"
                html_content += f"""
                <div class="vuln-item {severity_class}">
                    <div class="vuln-title">{vuln['type']} - {vuln['severity']} Risk</div>
                    <div class="vuln-desc">{vuln['description']}</div>
                    <div class="vuln-rec"><strong>Recommendation:</strong> {vuln['recommendation']}</div>
                </div>"""
            
            html_content += """
            </div>"""
        
        # Add ports section
        html_content += f"""
            <div class="section">
                <h2>🔌 Open Ports & Services</h2>
                <div class="port-grid">
"""
        
        open_ports = target.get('open_ports', [])
        for port in sorted(open_ports):
            service = self._get_service_name(port)
            html_content += f"""
                    <div class="port-item">
                        <div class="port-number">{port}</div>
                        <div>{service}</div>
                    </div>"""
        
        html_content += """
                </div>
            </div>
"""

        # Add SMB findings
        smb_findings = self.findings.get('smb', {})
        if smb_findings.get('shares'):
            html_content += """
            <div class="section">
                <h2>📁 SMB Shares Discovered</h2>
"""
            for share in smb_findings['shares']:
                html_content += f"""
                <div class="share-item">
                    <strong>{share['name']}</strong> ({share['type']}) - {share['comment']}
                </div>"""
            
            html_content += """
            </div>"""
        
        # Add LDAP findings
        ldap_findings = self.findings.get('ldap', {})
        if ldap_findings.get('kerberoastable'):
            html_content += """
            <div class="section">
                <h2>🎫 Kerberoastable Accounts</h2>
"""
            for account in ldap_findings['kerberoastable']:
                html_content += f"""
                <div class="finding-box">
                    <strong>User:</strong> {account['user']}<br>
                    <strong>SPN:</strong> {account['spn']}
                </div>"""
            
            html_content += """
            </div>"""
        
        # Add loot findings
        loot_findings = self.findings.get('loot', {})
        if loot_findings.get('hashes'):
            html_content += """
            <div class="section">
                <h2>💎 Extracted Credentials</h2>
"""
            for hash_info in loot_findings['hashes']:
                html_content += f"""
                <div class="finding-box">
                    {hash_info}
                </div>"""
            
            html_content += """
            </div>"""

        # Add conclusion
        html_content += f"""
            <div class="section">
                <h2>📋 Executive Summary</h2>
                <div class="info-box">
                    <p>This assessment identified <strong>{len(self.vulnerabilities)} security issues</strong> across the target system. 
                    The overall risk level is classified as <strong>{risk_level}</strong> based on the severity and number of vulnerabilities discovered.</p>
                    
                    <h4>Key Findings:</h4>
                    <ul>"""
        
        if any(v['severity'] == 'Critical' for v in self.vulnerabilities):
            html_content += "<li>🔴 <strong>Critical vulnerabilities</strong> require immediate attention</li>"
        if any(v['severity'] == 'High' for v in self.vulnerabilities):
            html_content += "<li>🟠 <strong>High-risk issues</strong> should be addressed promptly</li>"
        if smb_findings.get('shares'):
            html_content += f"<li>📁 <strong>{len(smb_findings['shares'])} SMB shares</strong> discovered and analyzed</li>"
        if ldap_findings.get('kerberoastable'):
            html_content += f"<li>🎫 <strong>{len(ldap_findings['kerberoastable'])} Kerberoastable accounts</strong> identified</li>"
        if not self.vulnerabilities:
            html_content += "<li>✅ No critical vulnerabilities identified in this assessment</li>"
            
        html_content += """
                    </ul>
                    
                    <h4>Recommendations:</h4>
                    <ul>
                        <li>Prioritize remediation of Critical and High-severity vulnerabilities</li>
                        <li>Review and harden SMB configurations and share permissions</li>
                        <li>Implement proper Kerberos security controls</li>
                        <li>Conduct regular security assessments and monitoring</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by WinRecon - Advanced Windows/Active Directory Security Assessment Tool</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
        
        # Write HTML file
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"Advanced HTML report generated: {output_file}")
    
    def generate_json_report(self, target: Dict, output_file: Path):
        """Generate comprehensive JSON report"""
        report_data = {
            'scan_info': {
                'tool': 'WinRecon',
                'version': '1.0',
                'scan_date': datetime.now().isoformat(),
                'target': target.get('target'),
                'scan_directory': str(target.get('scan_dir', ''))
            },
            'target_info': {
                'ip': target.get('target'),
                'hostname': target.get('hostname'),
                'domain': target.get('domain'),
                'os_detection': self.findings.get('nmap', {}).get('os_detection'),
                'open_ports': sorted(target.get('open_ports', [])),
                'services': target.get('services', {})
            },
            'vulnerabilities': self.vulnerabilities,
            'findings': self.findings,
            'risk_assessment': {
                'overall_score': self.calculate_risk_score(),
                'risk_level': self.get_risk_level(self.calculate_risk_score()),
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical_count': len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
                'high_count': len([v for v in self.vulnerabilities if v['severity'] == 'High']),
                'medium_count': len([v for v in self.vulnerabilities if v['severity'] == 'Medium']),
                'low_count': len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
            }
        }
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Advanced JSON report generated: {output_file}")
    
    def generate_text_summary(self, target: Dict, output_file: Path):
        """Generate detailed text summary"""
        risk_score = self.calculate_risk_score()
        risk_level = self.get_risk_level(risk_score)
        
        content = f"""WinRecon Advanced Security Assessment Report
============================================

Target: {target.get('target', 'Unknown')}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Overall Risk Level: {risk_level} (Score: {risk_score}/100)

EXECUTIVE SUMMARY
================
This assessment identified {len(self.vulnerabilities)} security issues across the target system.
Open Ports: {len(target.get('open_ports', []))}
Critical Vulnerabilities: {len([v for v in self.vulnerabilities if v['severity'] == 'Critical'])}
High Risk Issues: {len([v for v in self.vulnerabilities if v['severity'] == 'High'])}

TARGET INFORMATION
=================
IP Address: {target.get('target', 'N/A')}
Hostname: {target.get('hostname', 'N/A') or 'N/A'}
Domain: {target.get('domain', 'N/A') or 'N/A'}
Operating System: {self.findings.get('nmap', {}).get('os_detection', 'Unknown')}

OPEN PORTS & SERVICES
====================
"""
        
        open_ports = target.get('open_ports', [])
        if open_ports:
            for port in sorted(open_ports):
                service = self._get_service_name(port)
                content += f"{port:>6} - {service}\n"
        else:
            content += "No open ports detected\n"
        
        if self.vulnerabilities:
            content += f"""
SECURITY VULNERABILITIES
========================
"""
            for vuln in sorted(self.vulnerabilities, key=lambda x: {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}.get(x['severity'], 0), reverse=True):
                content += f"""
[{vuln['severity'].upper()}] {vuln['type']}
Description: {vuln['description']}
Recommendation: {vuln['recommendation']}
"""
        
        # Add detailed findings
        smb_findings = self.findings.get('smb', {})
        if smb_findings.get('shares'):
            content += f"""
SMB SHARES DISCOVERED
====================
"""
            for share in smb_findings['shares']:
                content += f"{share['name']:<15} {share['type']:<10} {share['comment']}\n"
        
        ldap_findings = self.findings.get('ldap', {})
        if ldap_findings.get('kerberoastable'):
            content += f"""
KERBEROASTABLE ACCOUNTS
======================
"""
            for account in ldap_findings['kerberoastable']:
                content += f"User: {account['user']} | SPN: {account['spn']}\n"
        
        loot_findings = self.findings.get('loot', {})
        if loot_findings.get('hashes'):
            content += f"""
EXTRACTED CREDENTIALS
====================
"""
            for hash_info in loot_findings['hashes']:
                content += f"{hash_info}\n"
        
        content += f"""
SCAN RESULTS LOCATION
====================
{target.get('scan_dir', 'N/A')}

Detailed results are available in:
- /scans/nmap/     - Port scanning and vulnerability detection
- /scans/smb/      - SMB enumeration and share analysis  
- /scans/ldap/     - LDAP/AD enumeration and user discovery
- /scans/web/      - Web service enumeration and directory discovery
- /loot/           - Extracted credentials, hashes, and tickets
- /report/         - Generated assessment reports

RECOMMENDATIONS
==============
1. Address all Critical and High-severity vulnerabilities immediately
2. Review and harden SMB share permissions and configurations
3. Implement proper Kerberos security controls and monitoring
4. Regularly assess and monitor the security posture
5. Apply security patches and updates consistently
"""
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        self.logger.info(f"Advanced text summary generated: {output_file}")
    
    def calculate_risk_score(self) -> int:
        """Calculate overall risk score based on vulnerabilities"""
        score = 0
        for vuln in self.vulnerabilities:
            if vuln['severity'] == 'Critical':
                score += 25
            elif vuln['severity'] == 'High':
                score += 15
            elif vuln['severity'] == 'Medium':
                score += 8
            elif vuln['severity'] == 'Low':
                score += 3
        
        return min(score, 100)  # Cap at 100
    
    def get_risk_level(self, score: int) -> str:
        """Get risk level based on score"""
        if score >= 75:
            return 'Critical'
        elif score >= 50:
            return 'High'
        elif score >= 25:
            return 'Medium'
        else:
            return 'Low'
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 111: 'RPC',
            135: 'RPC-EPMAP', 139: 'NetBIOS', 143: 'IMAP', 389: 'LDAP',
            443: 'HTTPS', 445: 'SMB', 464: 'Kerberos-Pwd', 636: 'LDAPS',
            1433: 'MSSQL', 3268: 'LDAP-GC', 3269: 'LDAPS-GC', 3389: 'RDP',
            5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 9389: 'AD-WebServices'
        }
        return common_ports.get(port, 'Unknown')