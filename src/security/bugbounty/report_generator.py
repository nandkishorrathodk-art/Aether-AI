"""
Bug Bounty Report Generator

Generates professional bug bounty reports in multiple formats
(Markdown, HTML, PDF) with all required sections for submission
to bug bounty platforms (HackerOne, Bugcrowd, etc.)
"""

import json
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Report output formats"""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    TEXT = "text"


class Platform(Enum):
    """Bug bounty platforms"""
    HACKERONE = "HackerOne"
    BUGCROWD = "Bugcrowd"
    INTIGRITI = "Intigriti"
    SYNACK = "Synack"
    YESWEHACK = "YesWeHack"
    CUSTOM = "Custom"


@dataclass
class BugReport:
    """Bug bounty report"""
    title: str
    vulnerability_type: str
    severity: str
    url: str
    
    # Required sections
    summary: str = ""
    description: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    proof_of_concept: str = ""
    impact: str = ""
    remediation: str = ""
    
    # Evidence
    screenshots: List[str] = field(default_factory=list)
    video_url: str = ""
    request_response: Dict[str, str] = field(default_factory=dict)
    
    # Classification
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    
    # Metadata
    researcher_name: str = "Aether AI Bug Hunter"
    discovered_date: datetime = field(default_factory=datetime.now)
    platform: Platform = Platform.CUSTOM
    program_name: str = ""
    
    # Payout estimate
    estimated_bounty: str = ""  # e.g., "$500-$1000"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "title": self.title,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "url": self.url,
            "summary": self.summary,
            "description": self.description,
            "steps_to_reproduce": self.steps_to_reproduce,
            "proof_of_concept": self.proof_of_concept,
            "impact": self.impact,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "discovered_date": self.discovered_date.isoformat(),
            "platform": self.platform.value,
            "program": self.program_name
        }


class ReportGenerator:
    """
    Professional bug bounty report generator
    
    Features:
    - Multiple output formats (Markdown, HTML, JSON)
    - Platform-specific formatting (HackerOne, Bugcrowd, etc.)
    - AI-powered report enhancement
    - CVSS score calculation
    - Impact analysis
    - Professional formatting
    """
    
    def __init__(self, ai_client=None):
        """
        Initialize report generator
        
        Args:
            ai_client: AI client for report enhancement
        """
        self.ai_client = ai_client
        
        # Platform-specific templates
        self.platform_templates = {
            Platform.HACKERONE: {
                "sections": [
                    "Summary", "Description", "Steps To Reproduce",
                    "Impact", "Mitigation", "Supporting Material/References"
                ],
                "severity_map": {
                    "Critical": "Critical",
                    "High": "High",
                    "Medium": "Medium",
                    "Low": "Low",
                    "Info": "None"
                }
            },
            Platform.BUGCROWD: {
                "sections": [
                    "Summary", "Proof of Concept", "Impact",
                    "Remediation", "References"
                ],
                "priority_map": {
                    "Critical": "P1",
                    "High": "P2",
                    "Medium": "P3",
                    "Low": "P4"
                }
            }
        }
    
    def generate_markdown(self, report: BugReport) -> str:
        """
        Generate Markdown format report
        
        Args:
            report: Bug report
            
        Returns:
            Markdown formatted report
        """
        md = []
        
        # Title
        md.append(f"# {report.title}\n")
        
        # Metadata table
        md.append("## Vulnerability Details\n")
        md.append("| Field | Value |")
        md.append("|-------|-------|")
        md.append(f"| **Type** | {report.vulnerability_type} |")
        md.append(f"| **Severity** | {report.severity} |")
        md.append(f"| **URL** | {report.url} |")
        
        if report.cvss_score:
            md.append(f"| **CVSS Score** | {report.cvss_score} |")
        if report.cwe_id:
            md.append(f"| **CWE** | {report.cwe_id} |")
        if report.owasp_category:
            md.append(f"| **OWASP** | {report.owasp_category} |")
        
        md.append(f"| **Discovered** | {report.discovered_date.strftime('%Y-%m-%d')} |")
        
        if report.estimated_bounty:
            md.append(f"| **Estimated Bounty** | {report.estimated_bounty} |")
        
        md.append("")
        
        # Summary
        md.append("## Summary\n")
        md.append(report.summary or "No summary provided")
        md.append("")
        
        # Description
        md.append("## Description\n")
        md.append(report.description or "No description provided")
        md.append("")
        
        # Steps to Reproduce
        md.append("## Steps to Reproduce\n")
        if report.steps_to_reproduce:
            for i, step in enumerate(report.steps_to_reproduce, 1):
                md.append(f"{i}. {step}")
        else:
            md.append("No steps provided")
        md.append("")
        
        # Proof of Concept
        md.append("## Proof of Concept\n")
        if report.proof_of_concept:
            md.append("```")
            md.append(report.proof_of_concept)
            md.append("```")
        else:
            md.append("No PoC provided")
        md.append("")
        
        # Impact
        md.append("## Impact\n")
        md.append(report.impact or "No impact analysis provided")
        md.append("")
        
        # Remediation
        md.append("## Remediation\n")
        md.append(report.remediation or "No remediation advice provided")
        md.append("")
        
        # Request/Response
        if report.request_response:
            md.append("## Supporting Evidence\n")
            
            if "request" in report.request_response:
                md.append("### HTTP Request\n")
                md.append("```http")
                md.append(report.request_response["request"])
                md.append("```\n")
            
            if "response" in report.request_response:
                md.append("### HTTP Response\n")
                md.append("```http")
                md.append(report.request_response["response"][:1000])  # Limit length
                md.append("```\n")
        
        # Screenshots
        if report.screenshots:
            md.append("## Screenshots\n")
            for i, screenshot in enumerate(report.screenshots, 1):
                md.append(f"{i}. {screenshot}")
            md.append("")
        
        # Video
        if report.video_url:
            md.append(f"## Video Demonstration\n")
            md.append(f"{report.video_url}\n")
        
        # Footer
        md.append("---\n")
        md.append(f"*Report generated by {report.researcher_name}*")
        md.append(f"*Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\n".join(md)
    
    def generate_html(self, report: BugReport) -> str:
        """
        Generate HTML format report
        
        Args:
            report: Bug report
            
        Returns:
            HTML formatted report
        """
        html = []
        
        html.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 900px;
            margin: 40px auto;
            padding: 20px;
            line-height: 1.6;
            color: #333;
        }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .metadata {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .metadata table {{ width: 100%; border-collapse: collapse; }}
        .metadata td {{ padding: 8px; border-bottom: 1px solid #bdc3c7; }}
        .metadata td:first-child {{ font-weight: bold; width: 200px; }}
        .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        .severity-high {{ color: #e67e22; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; font-weight: bold; }}
        .severity-low {{ color: #3498db; font-weight: bold; }}
        pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        code {{ background: #ecf0f1; padding: 2px 6px; border-radius: 3px; }}
        .steps {{ list-style-type: decimal; padding-left: 20px; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #bdc3c7; color: #7f8c8d; text-align: center; }}
    </style>
</head>
<body>""".format(title=report.title))
        
        html.append(f"<h1>{report.title}</h1>")
        
        # Metadata
        severity_class = f"severity-{report.severity.lower()}"
        html.append('<div class="metadata">')
        html.append('<table>')
        html.append(f'<tr><td>Vulnerability Type</td><td>{report.vulnerability_type}</td></tr>')
        html.append(f'<tr><td>Severity</td><td class="{severity_class}">{report.severity}</td></tr>')
        html.append(f'<tr><td>Affected URL</td><td>{report.url}</td></tr>')
        
        if report.cvss_score:
            html.append(f'<tr><td>CVSS Score</td><td>{report.cvss_score}</td></tr>')
        if report.program_name:
            html.append(f'<tr><td>Program</td><td>{report.program_name}</td></tr>')
        
        html.append('</table>')
        html.append('</div>')
        
        # Sections
        html.append(f'<h2>Summary</h2><p>{report.summary}</p>')
        html.append(f'<h2>Description</h2><p>{report.description}</p>')
        
        html.append('<h2>Steps to Reproduce</h2>')
        html.append('<ol class="steps">')
        for step in report.steps_to_reproduce:
            html.append(f'<li>{step}</li>')
        html.append('</ol>')
        
        if report.proof_of_concept:
            html.append(f'<h2>Proof of Concept</h2><pre><code>{report.proof_of_concept}</code></pre>')
        
        html.append(f'<h2>Impact</h2><p>{report.impact}</p>')
        html.append(f'<h2>Remediation</h2><p>{report.remediation}</p>')
        
        # Footer
        html.append('<div class="footer">')
        html.append(f'<p>Report generated by {report.researcher_name}</p>')
        html.append(f'<p>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')
        html.append('</div>')
        
        html.append('</body></html>')
        
        return "\n".join(html)
    
    def generate_json(self, report: BugReport) -> str:
        """
        Generate JSON format report
        
        Args:
            report: Bug report
            
        Returns:
            JSON formatted report
        """
        return json.dumps(report.to_dict(), indent=2)
    
    def generate_platform_specific(
        self,
        report: BugReport,
        platform: Platform
    ) -> str:
        """
        Generate platform-specific report
        
        Args:
            report: Bug report
            platform: Target platform
            
        Returns:
            Platform-formatted report
        """
        if platform == Platform.HACKERONE:
            return self._generate_hackerone(report)
        elif platform == Platform.BUGCROWD:
            return self._generate_bugcrowd(report)
        else:
            return self.generate_markdown(report)
    
    def _generate_hackerone(self, report: BugReport) -> str:
        """Generate HackerOne formatted report"""
        md = []
        
        md.append(f"**Title:** {report.title}\n")
        md.append(f"**Severity:** {report.severity}\n")
        
        md.append("## Summary\n")
        md.append(report.summary + "\n")
        
        md.append("## Steps To Reproduce\n")
        for i, step in enumerate(report.steps_to_reproduce, 1):
            md.append(f"{i}. {step}")
        md.append("")
        
        md.append("## Impact\n")
        md.append(report.impact + "\n")
        
        md.append("## Mitigation\n")
        md.append(report.remediation + "\n")
        
        if report.proof_of_concept:
            md.append("## Supporting Material/References\n")
            md.append("```")
            md.append(report.proof_of_concept)
            md.append("```\n")
        
        return "\n".join(md)
    
    def _generate_bugcrowd(self, report: BugReport) -> str:
        """Generate Bugcrowd formatted report"""
        md = []
        
        # Map severity to priority
        priority_map = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}
        priority = priority_map.get(report.severity, "P4")
        
        md.append(f"**Title:** {report.title}")
        md.append(f"**Priority:** {priority}")
        md.append(f"**VRT Classification:** {report.vulnerability_type}\n")
        
        md.append("## Summary\n")
        md.append(report.summary + "\n")
        
        md.append("## Proof of Concept\n")
        for i, step in enumerate(report.steps_to_reproduce, 1):
            md.append(f"{i}. {step}")
        md.append("")
        
        if report.proof_of_concept:
            md.append("```")
            md.append(report.proof_of_concept)
            md.append("```\n")
        
        md.append("## Impact\n")
        md.append(report.impact + "\n")
        
        md.append("## Remediation\n")
        md.append(report.remediation + "\n")
        
        return "\n".join(md)
    
    async def ai_enhance_report(self, report: BugReport) -> BugReport:
        """
        Use AI to enhance report quality
        
        Args:
            report: Bug report to enhance
            
        Returns:
            Enhanced bug report
        """
        if not self.ai_client:
            return report
        
        prompt = f"""Enhance this bug bounty report to make it more professional and comprehensive:

Title: {report.title}
Type: {report.vulnerability_type}
Severity: {report.severity}

Current Summary: {report.summary}
Current Impact: {report.impact}

Please provide:
1. Enhanced professional summary (2-3 sentences)
2. Detailed impact analysis with business context
3. Clear remediation steps for developers
4. Estimated CVSS score (if not provided)
5. Potential bounty range estimate

Format the response as JSON with keys: summary, impact, remediation, cvss_score, bounty_estimate
"""
        
        try:
            from src.cognitive.llm.model_loader import ModelLoader
            loader = ModelLoader()
            
            response = loader.generate(
                prompt=prompt,
                task_type="analysis",
                max_tokens=1000
            )
            
            # Try to parse JSON response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                enhancements = json.loads(json_match.group())
                
                report.summary = enhancements.get('summary', report.summary)
                report.impact = enhancements.get('impact', report.impact)
                report.remediation = enhancements.get('remediation', report.remediation)
                
                if 'cvss_score' in enhancements:
                    report.cvss_score = float(enhancements['cvss_score'])
                if 'bounty_estimate' in enhancements:
                    report.estimated_bounty = enhancements['bounty_estimate']
            
            logger.info("Report enhanced with AI")
            
        except Exception as e:
            logger.error(f"AI report enhancement failed: {e}")
        
        return report
    
    def save_report(
        self,
        report: BugReport,
        format: ReportFormat,
        filepath: str
    ):
        """
        Save report to file
        
        Args:
            report: Bug report
            format: Output format
            filepath: File path
        """
        if format == ReportFormat.MARKDOWN:
            content = self.generate_markdown(report)
        elif format == ReportFormat.HTML:
            content = self.generate_html(report)
        elif format == ReportFormat.JSON:
            content = self.generate_json(report)
        else:
            content = self.generate_markdown(report)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"Report saved to: {filepath}")


# Example usage
if __name__ == "__main__":
    # Create sample report
    report = BugReport(
        title="SQL Injection in User Search Parameter",
        vulnerability_type="SQL Injection",
        severity="High",
        url="https://example.com/search",
        summary="The user search functionality is vulnerable to SQL injection, allowing unauthorized database access.",
        description="The 'q' parameter in the search endpoint does not properly sanitize user input, allowing SQL injection attacks.",
        steps_to_reproduce=[
            "Navigate to https://example.com/search",
            "Enter the following payload in search box: ' OR '1'='1",
            "Submit the search",
            "Observe all user records are returned"
        ],
        proof_of_concept="curl \"https://example.com/search?q=' OR '1'='1--\"",
        impact="An attacker can access sensitive user data including emails, passwords, and personal information. This could lead to account takeover and data breach.",
        remediation="Use parameterized queries or prepared statements. Implement input validation and output encoding.",
        cvss_score=8.6,
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
        program_name="Example Bug Bounty Program",
        platform=Platform.HACKERONE,
        estimated_bounty="$500-$1500"
    )
    
    # Generate report
    generator = ReportGenerator()
    
    print("Markdown Report:")
    print("=" * 60)
    print(generator.generate_markdown(report))
    
    print("\n\nHackerOne Format:")
    print("=" * 60)
    print(generator.generate_platform_specific(report, Platform.HACKERONE))
