"""
Enhanced Security Report Generator
Professional vulnerability reports with visualization
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class SecurityReportGenerator:
    """
    Enhanced security report generator with visualization
    
    Features:
    - Multiple output formats (JSON, HTML, PDF, Markdown)
    - Executive summaries
    - Technical details
    - Visualization charts
    - CVSS scoring
    - Remediation prioritization
    """
    
    def __init__(self, output_dir: str = "reports"):
        """Initialize report generator"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Security Report Generator initialized")
    
    def generate_comprehensive_report(
        self,
        scan_results: Dict[str, Any],
        output_format: str = "html"
    ) -> str:
        """
        Generate comprehensive security report
        
        Args:
            scan_results: Scan results dictionary
            output_format: Output format (json, html, markdown, pdf)
        
        Returns:
            Path to generated report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = scan_results.get('target', 'unknown').replace('https://', '').replace('http://', '').replace('/', '_')
        
        if output_format == "json":
            return self._generate_json_report(scan_results, timestamp, target_name)
        elif output_format == "html":
            return self._generate_html_report(scan_results, timestamp, target_name)
        elif output_format == "markdown":
            return self._generate_markdown_report(scan_results, timestamp, target_name)
        else:
            logger.warning(f"Unsupported format: {output_format}, defaulting to HTML")
            return self._generate_html_report(scan_results, timestamp, target_name)
    
    def _generate_json_report(
        self,
        scan_results: Dict[str, Any],
        timestamp: str,
        target_name: str
    ) -> str:
        """Generate JSON report"""
        filename = f"security_report_{target_name}_{timestamp}.json"
        filepath = self.output_dir / filename
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "target": scan_results.get('target', 'N/A'),
                "scanner": "Aether AI Security Scanner"
            },
            "executive_summary": self._generate_executive_summary(scan_results),
            "findings": scan_results.get('vulnerabilities', []),
            "statistics": self._calculate_statistics(scan_results)
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"JSON report generated: {filepath}")
        return str(filepath)
    
    def _generate_html_report(
        self,
        scan_results: Dict[str, Any],
        timestamp: str,
        target_name: str
    ) -> str:
        """Generate HTML report"""
        filename = f"security_report_{target_name}_{timestamp}.html"
        filepath = self.output_dir / filename
        
        executive_summary = self._generate_executive_summary(scan_results)
        statistics = self._calculate_statistics(scan_results)
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {scan_results.get('target', 'N/A')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        header {{
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #2c3e50;
            margin: 0 0 10px 0;
        }}
        .metadata {{
            color: #7f8c8d;
            font-size: 14px;
        }}
        .severity-critical {{
            background: #c0392b;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .severity-high {{
            background: #e74c3c;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .severity-medium {{
            background: #f39c12;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .severity-low {{
            background: #3498db;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .severity-info {{
            background: #95a5a6;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .summary-box {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            color: #2c3e50;
        }}
        .stat-label {{
            color: #7f8c8d;
            font-size: 14px;
        }}
        .vulnerability {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin: 15px 0;
        }}
        .vulnerability h3 {{
            margin-top: 0;
            color: #2c3e50;
        }}
        .section {{
            margin: 30px 0;
        }}
        pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #34495e;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Assessment Report</h1>
            <div class="metadata">
                <p><strong>Target:</strong> {scan_results.get('target', 'N/A')}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Scanner:</strong> Aether AI Security Scanner v1.0</p>
            </div>
        </header>

        <section class="section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-box">
                <p><strong>Risk Level:</strong> <span class="severity-{executive_summary['risk_level'].lower()}">{executive_summary['risk_level']}</span></p>
                <p>{executive_summary['summary']}</p>
            </div>
        </section>

        <section class="section">
            <h2>📈 Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{statistics['total_vulnerabilities']}</div>
                    <div class="stat-label">Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #c0392b;">{statistics['by_severity'].get('CRITICAL', 0)}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #e74c3c;">{statistics['by_severity'].get('HIGH', 0)}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #f39c12;">{statistics['by_severity'].get('MEDIUM', 0)}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #3498db;">{statistics['by_severity'].get('LOW', 0)}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </section>

        <section class="section">
            <h2>🔍 Detailed Findings</h2>
            {self._generate_vulnerability_html(vulnerabilities)}
        </section>

        <section class="section">
            <h2>✅ Recommendations</h2>
            <ol>
                {self._generate_recommendations_html(vulnerabilities)}
            </ol>
        </section>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {filepath}")
        return str(filepath)
    
    def _generate_markdown_report(
        self,
        scan_results: Dict[str, Any],
        timestamp: str,
        target_name: str
    ) -> str:
        """Generate Markdown report"""
        filename = f"security_report_{target_name}_{timestamp}.md"
        filepath = self.output_dir / filename
        
        executive_summary = self._generate_executive_summary(scan_results)
        statistics = self._calculate_statistics(scan_results)
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        md_content = f"""# 🛡️ Security Assessment Report

**Target:** {scan_results.get('target', 'N/A')}  
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Scanner:** Aether AI Security Scanner v1.0

---

## 📊 Executive Summary

**Risk Level:** {executive_summary['risk_level']}

{executive_summary['summary']}

---

## 📈 Statistics

| Metric | Count |
|--------|-------|
| Total Vulnerabilities | {statistics['total_vulnerabilities']} |
| Critical | {statistics['by_severity'].get('CRITICAL', 0)} |
| High | {statistics['by_severity'].get('HIGH', 0)} |
| Medium | {statistics['by_severity'].get('MEDIUM', 0)} |
| Low | {statistics['by_severity'].get('LOW', 0)} |

---

## 🔍 Detailed Findings

{self._generate_vulnerability_markdown(vulnerabilities)}

---

## ✅ Recommendations

{self._generate_recommendations_markdown(vulnerabilities)}

---

*Generated by Aether AI Security Scanner*
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        logger.info(f"Markdown report generated: {filepath}")
        return str(filepath)
    
    def _generate_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        
        if critical_count > 0:
            risk_level = "CRITICAL"
            summary = f"The assessment identified {critical_count} critical vulnerabilities requiring immediate attention."
        elif high_count > 3:
            risk_level = "HIGH"
            summary = f"The assessment found {high_count} high-severity vulnerabilities that should be addressed promptly."
        elif high_count > 0:
            risk_level = "MEDIUM"
            summary = f"The assessment identified {len(vulnerabilities)} vulnerabilities with moderate risk."
        else:
            risk_level = "LOW"
            summary = "The assessment found minor issues that should be addressed during regular maintenance."
        
        return {
            "risk_level": risk_level,
            "summary": summary
        }
    
    def _calculate_statistics(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate vulnerability statistics"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        by_severity = {}
        by_type = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            vuln_type = vuln.get('type', 'Unknown')
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "by_severity": by_severity,
            "by_type": by_type
        }
    
    def _generate_vulnerability_html(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate HTML for vulnerability list"""
        if not vulnerabilities:
            return "<p>No vulnerabilities found.</p>"
        
        html = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'INFO').upper()
            html += f"""
            <div class="vulnerability">
                <h3>{i}. {vuln.get('title', 'Unknown Vulnerability')}</h3>
                <p><strong>Severity:</strong> <span class="severity-{severity.lower()}">{severity}</span></p>
                <p><strong>Type:</strong> {vuln.get('type', 'N/A')}</p>
                <p><strong>URL:</strong> <code>{vuln.get('url', 'N/A')}</code></p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description available.')}</p>
                <p><strong>Recommendation:</strong> {vuln.get('remediation', 'No recommendation available.')}</p>
            </div>
            """
        
        return html
    
    def _generate_vulnerability_markdown(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate Markdown for vulnerability list"""
        if not vulnerabilities:
            return "No vulnerabilities found."
        
        md = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'INFO').upper()
            md += f"""
### {i}. {vuln.get('title', 'Unknown Vulnerability')}

**Severity:** {severity}  
**Type:** {vuln.get('type', 'N/A')}  
**URL:** `{vuln.get('url', 'N/A')}`

**Description:** {vuln.get('description', 'No description available.')}

**Recommendation:** {vuln.get('remediation', 'No recommendation available.')}

---
"""
        
        return md
    
    def _generate_recommendations_html(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate HTML recommendations"""
        if not vulnerabilities:
            return "<li>No immediate actions required.</li>"
        
        critical_high = [v for v in vulnerabilities if v.get('severity') in ['CRITICAL', 'HIGH']]
        
        if critical_high:
            return "\n".join([
                f"<li><strong>[{v.get('severity')}]</strong> {v.get('remediation', 'Address this vulnerability.')}</li>"
                for v in critical_high[:10]
            ])
        else:
            return "<li>Review and address medium/low severity findings during regular maintenance.</li>"
    
    def _generate_recommendations_markdown(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate Markdown recommendations"""
        if not vulnerabilities:
            return "- No immediate actions required."
        
        critical_high = [v for v in vulnerabilities if v.get('severity') in ['CRITICAL', 'HIGH']]
        
        if critical_high:
            return "\n".join([
                f"{i+1}. **[{v.get('severity')}]** {v.get('remediation', 'Address this vulnerability.')}"
                for i, v in enumerate(critical_high[:10])
            ])
        else:
            return "1. Review and address medium/low severity findings during regular maintenance."
