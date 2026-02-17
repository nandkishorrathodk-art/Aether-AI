"""
Report Builder

Professional bug bounty report generation in multiple formats.
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
import json

from src.bugbounty.models import (
    BugReport, Vulnerability, ProofOfConcept, VulnerabilitySeverity
)
from src.config import settings

logger = logging.getLogger(__name__)


class ReportBuilder:
    """
    Build professional bug bounty reports
    
    Features:
    - Multiple formats (Markdown, HTML, JSON)
    - Platform-specific templates
    - Severity-based CVSS scoring
    - Payout estimation
    - Screenshot integration
    - Professional formatting
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize report builder
        
        Args:
            output_dir: Directory for report output
        """
        self.output_dir = output_dir or settings.bugbounty_report_path
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"ReportBuilder initialized with output: {self.output_dir}")
    
    def build_report(
        self,
        vulnerability: Vulnerability,
        poc: ProofOfConcept,
        program: str = "general"
    ) -> BugReport:
        """
        Build complete bug report
        
        Args:
            vulnerability: Vulnerability details
            poc: Proof of concept
            program: Bug bounty program name
            
        Returns:
            BugReport object
        """
        min_payout, max_payout = vulnerability.estimate_payout(program)
        
        report = BugReport(
            title=f"[{vulnerability.severity.value.upper()}] {vulnerability.title}",
            vulnerability=vulnerability,
            poc=poc,
            summary=self._generate_summary(vulnerability),
            impact=self._generate_impact(vulnerability),
            reproduction_steps=poc.steps,
            affected_urls=[vulnerability.url],
            fix_recommendation=vulnerability.remediation or self._generate_fix_recommendation(vulnerability),
            program=program,
            estimated_payout_min=min_payout,
            estimated_payout_max=max_payout
        )
        
        logger.info(f"Built report: {report.title}")
        return report
    
    def generate_markdown_report(self, report: BugReport) -> str:
        """Generate Markdown report"""
        
        md = f"""# {report.title}

**Reported by:** {report.reporter_name}  
**Program:** {report.program}  
**Date:** {report.created_at.strftime("%Y-%m-%d")}  
**Severity:** {report.vulnerability.severity.to_emoji()} {report.vulnerability.severity.value.upper()}  
**CVSS Score:** {report.vulnerability.cvss_score}  
**Estimated Payout:** ${report.estimated_payout_min:,} - ${report.estimated_payout_max:,}

---

## Summary

{report.summary}

---

## Vulnerability Details

**Type:** {report.vulnerability.vuln_type.value}  
**Affected URL:** {report.vulnerability.url}  
**Parameter:** {report.vulnerability.parameter or 'N/A'}  
**Confidence:** {report.vulnerability.confidence}

### Description

{report.vulnerability.description}

### Evidence

```
{report.vulnerability.evidence[:500]}
```

---

## Impact

{report.impact}

---

## Steps to Reproduce

"""
        
        for i, step in enumerate(report.reproduction_steps, 1):
            md += f"{i}. {step}\n"
        
        md += f"""
---

## Proof of Concept

**Type:** {report.poc.exploit_type}  
**WAF Bypass:** {"Yes ✓" if report.poc.waf_bypass else "No"}  
**Safe for Production:** {"Yes ✓" if report.poc.safe_for_production else "No ⚠"}

### Exploit Code

```python
{report.poc.exploit_code}
```

### Expected Result

{report.poc.expected_result}

---

## Remediation

{report.fix_recommendation}

---

## References

"""
        
        if report.vulnerability.cwe_id:
            md += f"- CWE: {report.vulnerability.cwe_id}\n"
        
        for ref in report.vulnerability.references:
            md += f"- {ref}\n"
        
        md += "\n---\n\n"
        md += f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n"
        md += "**Powered by:** Aether AI Bug Bounty Autopilot v0.9.0\n"
        
        return md
    
    def generate_html_report(self, report: BugReport) -> str:
        """Generate HTML report"""
        
        severity_colors = {
            VulnerabilitySeverity.CRITICAL: "#dc3545",
            VulnerabilitySeverity.HIGH: "#fd7e14",
            VulnerabilitySeverity.MEDIUM: "#ffc107",
            VulnerabilitySeverity.LOW: "#17a2b8",
            VulnerabilitySeverity.INFO: "#6c757d"
        }
        
        color = severity_colors.get(report.vulnerability.severity, "#6c757d")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .header {{
            background: linear-gradient(135deg, {color} 0%, {color}dd 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0 0 15px 0;
            font-size: 2em;
        }}
        .header .meta {{
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
        }}
        .header .meta-item {{
            display: flex;
            flex-direction: column;
        }}
        .header .meta-label {{
            font-size: 0.85em;
            opacity: 0.9;
        }}
        .header .meta-value {{
            font-size: 1.1em;
            font-weight: bold;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: {color};
            border-bottom: 2px solid {color};
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            background: {color};
            color: white;
            font-weight: bold;
            font-size: 1.1em;
        }}
        .code-block {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
        }}
        .steps {{
            list-style: none;
            counter-reset: step-counter;
            padding-left: 0;
        }}
        .steps li {{
            counter-increment: step-counter;
            margin-bottom: 15px;
            padding-left: 40px;
            position: relative;
        }}
        .steps li::before {{
            content: counter(step-counter);
            position: absolute;
            left: 0;
            top: 0;
            background: {color};
            color: white;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .info-item {{
            padding: 10px;
            background: #f8f9fa;
            border-left: 3px solid {color};
            border-radius: 3px;
        }}
        .info-label {{
            font-weight: bold;
            color: {color};
            font-size: 0.85em;
            text-transform: uppercase;
        }}
        .info-value {{
            margin-top: 5px;
            font-size: 1em;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report.title}</h1>
        <div class="meta">
            <div class="meta-item">
                <span class="meta-label">Severity</span>
                <span class="meta-value">{report.vulnerability.severity.to_emoji()} {report.vulnerability.severity.value.upper()}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">CVSS Score</span>
                <span class="meta-value">{report.vulnerability.cvss_score}/10.0</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Estimated Payout</span>
                <span class="meta-value">${report.estimated_payout_min:,} - ${report.estimated_payout_max:,}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Program</span>
                <span class="meta-value">{report.program}</span>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>📋 Summary</h2>
        <p>{report.summary}</p>
    </div>

    <div class="section">
        <h2>🔍 Vulnerability Details</h2>
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">Type</div>
                <div class="info-value">{report.vulnerability.vuln_type.value}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Affected URL</div>
                <div class="info-value">{report.vulnerability.url}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Parameter</div>
                <div class="info-value">{report.vulnerability.parameter or 'N/A'}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Confidence</div>
                <div class="info-value">{report.vulnerability.confidence}</div>
            </div>
        </div>
        
        <h3>Description</h3>
        <p>{report.vulnerability.description}</p>
        
        <h3>Evidence</h3>
        <div class="code-block">{report.vulnerability.evidence[:500]}</div>
    </div>

    <div class="section">
        <h2>⚠️ Impact</h2>
        <p>{report.impact}</p>
    </div>

    <div class="section">
        <h2>🔄 Steps to Reproduce</h2>
        <ol class="steps">
"""
        
        for step in report.reproduction_steps:
            html += f"            <li>{step}</li>\n"
        
        html += f"""        </ol>
    </div>

    <div class="section">
        <h2>💻 Proof of Concept</h2>
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">Type</div>
                <div class="info-value">{report.poc.exploit_type}</div>
            </div>
            <div class="info-item">
                <div class="info-label">WAF Bypass</div>
                <div class="info-value">{"Yes ✓" if report.poc.waf_bypass else "No"}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Safe for Production</div>
                <div class="info-value">{"Yes ✓" if report.poc.safe_for_production else "No ⚠"}</div>
            </div>
        </div>
        
        <h3>Exploit Code</h3>
        <div class="code-block">{report.poc.exploit_code.replace('<', '&lt;').replace('>', '&gt;')}</div>
        
        <h3>Expected Result</h3>
        <p>{report.poc.expected_result}</p>
    </div>

    <div class="section">
        <h2>🛠️ Remediation</h2>
        <p>{report.fix_recommendation}</p>
    </div>

    <div class="section">
        <h2>📚 References</h2>
        <ul>
"""
        
        if report.vulnerability.cwe_id:
            html += f"            <li>CWE: {report.vulnerability.cwe_id}</li>\n"
        
        for ref in report.vulnerability.references:
            html += f"            <li>{ref}</li>\n"
        
        html += f"""        </ul>
    </div>

    <div class="footer">
        <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Powered by:</strong> Aether AI Bug Bounty Autopilot v0.9.0</p>
    </div>
</body>
</html>"""
        
        return html
    
    def generate_json_report(self, report: BugReport) -> str:
        """Generate JSON report"""
        return json.dumps(report.to_dict(), indent=2)
    
    def save_report(
        self,
        report: BugReport,
        formats: List[str] = ["markdown", "html", "json"]
    ) -> Dict[str, Path]:
        """
        Save report in multiple formats
        
        Args:
            report: Bug report to save
            formats: List of formats ("markdown", "html", "json")
            
        Returns:
            Dictionary of format -> file path
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(c for c in report.title if c.isalnum() or c in (' ', '-', '_')).strip()
        safe_title = safe_title.replace(' ', '_')[:50]
        
        base_filename = f"bugbounty_{safe_title}_{timestamp}"
        
        saved_files = {}
        
        if "markdown" in formats:
            md_content = self.generate_markdown_report(report)
            md_path = self.output_dir / f"{base_filename}.md"
            md_path.write_text(md_content, encoding='utf-8')
            saved_files["markdown"] = md_path
            logger.info(f"Saved Markdown report: {md_path}")
        
        if "html" in formats:
            html_content = self.generate_html_report(report)
            html_path = self.output_dir / f"{base_filename}.html"
            html_path.write_text(html_content, encoding='utf-8')
            saved_files["html"] = html_path
            logger.info(f"Saved HTML report: {html_path}")
        
        if "json" in formats:
            json_content = self.generate_json_report(report)
            json_path = self.output_dir / f"{base_filename}.json"
            json_path.write_text(json_content, encoding='utf-8')
            saved_files["json"] = json_path
            logger.info(f"Saved JSON report: {json_path}")
        
        return saved_files
    
    def _generate_summary(self, vuln: Vulnerability) -> str:
        """Generate vulnerability summary"""
        return f"""A {vuln.severity.value} severity {vuln.vuln_type.value} vulnerability has been identified in the application. This vulnerability allows an attacker to potentially compromise the security of the application and its users. The issue was discovered through automated security testing and has been confirmed with a proof of concept."""
    
    def _generate_impact(self, vuln: Vulnerability) -> str:
        """Generate impact statement"""
        
        impact_templates = {
            VulnerabilitySeverity.CRITICAL: "This critical vulnerability poses a severe risk to the application and its users. Exploitation could lead to complete system compromise, data breach, or severe service disruption. Immediate remediation is strongly recommended.",
            
            VulnerabilitySeverity.HIGH: "This high-severity vulnerability poses significant risk. Successful exploitation could result in unauthorized access to sensitive data, privilege escalation, or compromise of user accounts. Prompt remediation is recommended.",
            
            VulnerabilitySeverity.MEDIUM: "This medium-severity vulnerability could allow an attacker to compromise application security or user data under certain conditions. While exploitation may require specific circumstances, remediation should be prioritized.",
            
            VulnerabilitySeverity.LOW: "This low-severity vulnerability has limited impact but should still be addressed. While direct exploitation is unlikely to cause severe damage, it could be chained with other vulnerabilities for greater impact.",
            
            VulnerabilitySeverity.INFO: "This informational finding highlights a potential security concern that, while not directly exploitable, could aid an attacker in reconnaissance or future attacks. Addressing this issue improves overall security posture."
        }
        
        return impact_templates.get(vuln.severity, "Impact assessment pending.")
    
    def _generate_fix_recommendation(self, vuln: Vulnerability) -> str:
        """Generate fix recommendation"""
        
        fix_templates = {
            VulnerabilityType.XSS: "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Sanitize user input before rendering in HTML context.",
            
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements. Implement input validation. Apply principle of least privilege for database accounts.",
            
            VulnerabilityType.CSRF: "Implement anti-CSRF tokens for state-changing operations. Use SameSite cookie attribute. Verify Origin/Referer headers.",
            
            VulnerabilityType.IDOR: "Implement proper access control checks. Use indirect references or encrypted IDs. Validate user authorization for each resource access.",
            
            VulnerabilityType.LFI: "Implement strict input validation and whitelist allowed files. Use absolute paths. Disable directory traversal in web server configuration.",
            
            VulnerabilityType.SSRF: "Implement URL whitelist validation. Use network segmentation. Block access to internal IP ranges and metadata endpoints.",
        }
        
        return fix_templates.get(
            vuln.vuln_type,
            "Review and implement security best practices for this vulnerability type. Consult OWASP guidelines and security documentation."
        )
