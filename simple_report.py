#!/usr/bin/env python3
"""
Simple Report Generator for WinRecon
A simplified version that's guaranteed to work
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

class SimpleReportGenerator:
    """Simple report generator for WinRecon"""
    
    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
    
    def generate_reports(self, target: Dict, target_dir: Path):
        """Generate all report formats"""
        try:
            # Generate HTML report
            if self.config.get('reporting', {}).get('generate_html', True):
                self.generate_html_report(target, target_dir / 'report' / 'report.html')
            
            # Generate JSON report
            if self.config.get('reporting', {}).get('generate_json', True):
                self.generate_json_report(target, target_dir / 'report' / 'report.json')
            
            # Generate text summary
            self.generate_text_summary(target, target_dir / 'report' / 'summary.txt')
            
            return True
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return False
    
    def generate_html_report(self, target: Dict, output_file: Path):
        """Generate simple HTML report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>WinRecon Report - {target.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .info-box {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border: 1px solid #dee2e6; }}
        .info-box h3 {{ margin-top: 0; color: #495057; }}
        .services {{ margin: 20px 0; }}
        .service-item {{ background: #e9ecef; padding: 10px; margin: 5px 0; border-radius: 4px; }}
        .port {{ font-weight: bold; color: #007bff; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; text-align: center; color: #6c757d; }}
        .status-good {{ color: #28a745; }}
        .status-warning {{ color: #ffc107; }}
        .status-danger {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ WinRecon Security Assessment Report</h1>
        
        <div class="info-grid">
            <div class="info-box">
                <h3>Target Information</h3>
                <p><strong>IP Address:</strong> {target.get('target', 'N/A')}</p>
                <p><strong>Hostname:</strong> {target.get('hostname', 'N/A') or 'N/A'}</p>
                <p><strong>Domain:</strong> {target.get('domain', 'N/A') or 'N/A'}</p>
            </div>
            
            <div class="info-box">
                <h3>Scan Details</h3>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Open Ports:</strong> {len(target.get('open_ports', []))}</p>
                <p><strong>Scan Directory:</strong> {target.get('scan_dir', 'N/A')}</p>
            </div>
        </div>
        
        <h2>📊 Port Summary</h2>
        <div class="services">
"""
        
        # Add open ports
        open_ports = target.get('open_ports', [])
        if open_ports:
            for port in sorted(open_ports):
                service = self._get_service_name(port)
                html_content += f'            <div class="service-item">Port <span class="port">{port}</span> - {service}</div>\n'
        else:
            html_content += '            <div class="service-item">No open ports detected</div>\n'
        
        html_content += """        </div>
        
        <h2>🔍 Service Analysis</h2>
        <div class="services">
"""
        
        # Service-specific analysis
        services_found = []
        if 445 in open_ports or 139 in open_ports:
            services_found.append(('SMB/NetBIOS', 'File sharing and Windows networking services detected', 'warning'))
        if 389 in open_ports or 636 in open_ports:
            services_found.append(('LDAP/LDAPS', 'Directory services detected - likely a Domain Controller', 'warning'))
        if 88 in open_ports:
            services_found.append(('Kerberos', 'Authentication service detected - confirms Domain Controller', 'warning'))
        if 80 in open_ports or 443 in open_ports:
            services_found.append(('Web Services', 'HTTP/HTTPS services detected', 'good'))
        if 3389 in open_ports:
            services_found.append(('RDP', 'Remote Desktop Protocol detected', 'danger'))
        if 5985 in open_ports or 5986 in open_ports:
            services_found.append(('WinRM', 'Windows Remote Management detected', 'warning'))
        
        if services_found:
            for service, desc, status in services_found:
                html_content += f'            <div class="service-item"><strong class="status-{status}">{service}:</strong> {desc}</div>\n'
        else:
            html_content += '            <div class="service-item">No critical services detected</div>\n'
        
        html_content += f"""        </div>
        
        <h2>📁 Output Files</h2>
        <div class="info-box">
            <p>Detailed scan results are available in the following directories:</p>
            <ul>
                <li><strong>Nmap Scans:</strong> {target.get('scan_dir', '')}/scans/nmap/</li>
                <li><strong>SMB Enumeration:</strong> {target.get('scan_dir', '')}/scans/smb/</li>
                <li><strong>LDAP Enumeration:</strong> {target.get('scan_dir', '')}/scans/ldap/</li>
                <li><strong>Web Enumeration:</strong> {target.get('scan_dir', '')}/scans/web/</li>
                <li><strong>Credentials/Hashes:</strong> {target.get('scan_dir', '')}/loot/</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by WinRecon - Windows/Active Directory Enumeration Tool</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
        
        # Write HTML file
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {output_file}")
    
    def generate_json_report(self, target: Dict, output_file: Path):
        """Generate JSON report"""
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
                'open_ports': sorted(target.get('open_ports', [])),
                'services': target.get('services', {})
            },
            'findings': {
                'total_open_ports': len(target.get('open_ports', [])),
                'critical_services': self._identify_critical_services(target.get('open_ports', []))
            }
        }
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"JSON report generated: {output_file}")
    
    def generate_text_summary(self, target: Dict, output_file: Path):
        """Generate text summary"""
        content = f"""WinRecon Scan Summary
====================

Target: {target.get('target', 'Unknown')}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Target Information:
------------------
IP Address: {target.get('target', 'N/A')}
Hostname: {target.get('hostname', 'N/A') or 'N/A'}
Domain: {target.get('domain', 'N/A') or 'N/A'}

Open Ports:
-----------
"""
        
        open_ports = target.get('open_ports', [])
        if open_ports:
            for port in sorted(open_ports):
                service = self._get_service_name(port)
                content += f"{port:>6} - {service}\n"
        else:
            content += "No open ports detected\n"
        
        content += f"""
Scan Results Location:
---------------------
{target.get('scan_dir', 'N/A')}

For detailed results, check the subdirectories:
- /scans/nmap/     - Port scanning results
- /scans/smb/      - SMB enumeration
- /scans/ldap/     - LDAP/AD enumeration
- /scans/web/      - Web service enumeration
- /loot/           - Extracted credentials and hashes
- /report/         - Generated reports
"""
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        self.logger.info(f"Text summary generated: {output_file}")
    
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
    
    def _identify_critical_services(self, open_ports: List[int]) -> List[Dict]:
        """Identify critical services from open ports"""
        critical = []
        
        if 445 in open_ports or 139 in open_ports:
            critical.append({'service': 'SMB', 'risk': 'high', 'description': 'File sharing service'})
        if 389 in open_ports or 636 in open_ports:
            critical.append({'service': 'LDAP', 'risk': 'medium', 'description': 'Directory service'})
        if 88 in open_ports:
            critical.append({'service': 'Kerberos', 'risk': 'medium', 'description': 'Authentication service'})
        if 3389 in open_ports:
            critical.append({'service': 'RDP', 'risk': 'high', 'description': 'Remote desktop'})
        if 5985 in open_ports or 5986 in open_ports:
            critical.append({'service': 'WinRM', 'risk': 'high', 'description': 'Remote management'})
        if 1433 in open_ports:
            critical.append({'service': 'MSSQL', 'risk': 'high', 'description': 'Database server'})
        
        return critical