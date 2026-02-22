"""
Professional Report Generator for Bug Bounty Submissions
Generates HTML, Markdown, and PDF reports
"""
import asyncio
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import base64

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """
    Professional report generator for bug bounty submissions.
    
    Features:
    - HTML reports (styled, interactive)
    - Markdown reports (GitHub-friendly)
    - JSON reports (machine-readable)
    - CVSS scoring integration
    - Screenshot embedding
    - PoC code highlighting
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory to save reports (default: ./reports)
        """
        self.output_dir = output_dir or Path("./reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Report Generator initialized")
    
    async def generate_bug_bounty_report(
        self,
        vulnerability: Dict,
        target: str,
        format: str = "markdown"
    ) -> str:
        """
        Generate professional bug bounty report.
        
        Args:
            vulnerability: Vulnerability details
            target: Target URL/domain
            format: Report format (markdown, html, json)
        
        Returns:
            Path to generated report
        """
        try:
            # Generate unique report ID
            report_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Generate report based on format
            if format == "markdown":
                content = self._generate_markdown_report(vulnerability, target, report_id)
                file_path = self.output_dir / f"report_{report_id}.md"
            
            elif format == "html":
                content = self._generate_html_report(vulnerability, target, report_id)
                file_path = self.output_dir / f"report_{report_id}.html"
            
            elif format == "json":
                import json
                content = json.dumps({
                    "report_id": report_id,
                    "target": target,
                    "vulnerability": vulnerability,
                    "generated_at": datetime.now().isoformat()
                }, indent=2)
                file_path = self.output_dir / f"report_{report_id}.json"
            
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            # Save report
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"Report generated: {file_path}")
            
            return str(file_path)
        
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            raise
    
    def _generate_markdown_report(
        self,
        vuln: Dict,
        target: str,
        report_id: str
    ) -> str:
        """Generate Markdown report."""
        
        severity = vuln.get("severity", "UNKNOWN").upper()
        cvss_score = vuln.get("cvss_score", 0.0)
        
        report = f"""# Vulnerability Report: {vuln.get('title', 'Untitled')}

**Report ID**: `{report_id}`  
**Target**: `{target}`  
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Severity**: **{severity}** (CVSS: {cvss_score})

---

## 📋 Executive Summary

{vuln.get('description', 'No description provided')}

---

## 🎯 Vulnerability Details

### Type
{vuln.get('type', 'Unknown')}

### Impact
{vuln.get('impact', 'Impact not specified')}

### Affected Components
- URL: `{target}`
- Parameter: `{vuln.get('parameter', 'N/A')}`
- Method: `{vuln.get('method', 'N/A')}`

---

## 🔍 Steps to Reproduce

{self._format_reproduction_steps(vuln.get('reproduction_steps', []))}

---

## 💡 Proof of Concept

```{vuln.get('poc_language', 'bash')}
{vuln.get('poc_code', 'No PoC provided')}
```

---

## 🛡️ Remediation

{vuln.get('remediation', 'Remediation steps not provided')}

---

## 📊 CVSS Breakdown

{self._format_cvss_breakdown(vuln.get('cvss_vector', ''))}

---

## 📸 Evidence

{self._format_evidence(vuln.get('evidence', []))}

---

## 📚 References

{self._format_references(vuln.get('references', []))}

---

**Reported by**: Aether AI Hybrid Edition  
**Report generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}
"""
        
        return report
    
    def _generate_html_report(
        self,
        vuln: Dict,
        target: str,
        report_id: str
    ) -> str:
        """Generate HTML report with styling."""
        
        severity = vuln.get("severity", "UNKNOWN").upper()
        severity_color = self._get_severity_color(severity)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report - {report_id}</title>
    <style>
        :root {{
            --primary-color: #2563eb;
            --danger-color: #dc2626;
            --warning-color: #f59e0b;
            --success-color: #10b981;
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --border-color: #e2e8f0;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 40px;
        }}
        
        h1 {{
            color: var(--primary-color);
            margin-bottom: 20px;
            font-size: 2.5em;
        }}
        
        .meta {{
            background: var(--bg-color);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        
        .meta-item {{
            margin-bottom: 10px;
        }}
        
        .meta-label {{
            font-weight: 600;
            color: #64748b;
            display: inline-block;
            width: 120px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: 600;
            color: white;
            background-color: {severity_color};
        }}
        
        .section {{
            margin: 30px 0;
        }}
        
        .section-title {{
            color: var(--primary-color);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        
        pre {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 15px 0;
        }}
        
        code {{
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .steps {{
            list-style: none;
            counter-reset: step-counter;
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
            background: var(--primary-color);
            color: white;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
        }}
        
        .evidence-item {{
            margin: 15px 0;
            padding: 15px;
            background: var(--bg-color);
            border-left: 4px solid var(--primary-color);
            border-radius: 4px;
        }}
        
        .footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid var(--border-color);
            text-align: center;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ {vuln.get('title', 'Vulnerability Report')}</h1>
        
        <div class="meta">
            <div class="meta-item">
                <span class="meta-label">Report ID:</span>
                <code>{report_id}</code>
            </div>
            <div class="meta-item">
                <span class="meta-label">Target:</span>
                <code>{target}</code>
            </div>
            <div class="meta-item">
                <span class="meta-label">Date:</span>
                {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
            <div class="meta-item">
                <span class="meta-label">Severity:</span>
                <span class="severity-badge">{severity} (CVSS: {vuln.get('cvss_score', 0.0)})</span>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">📋 Executive Summary</h2>
            <p>{vuln.get('description', 'No description provided')}</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">🎯 Vulnerability Details</h2>
            <p><strong>Type:</strong> {vuln.get('type', 'Unknown')}</p>
            <p><strong>Impact:</strong> {vuln.get('impact', 'Impact not specified')}</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">🔍 Steps to Reproduce</h2>
            {self._format_reproduction_steps_html(vuln.get('reproduction_steps', []))}
        </div>
        
        <div class="section">
            <h2 class="section-title">💡 Proof of Concept</h2>
            <pre><code>{vuln.get('poc_code', 'No PoC provided')}</code></pre>
        </div>
        
        <div class="section">
            <h2 class="section-title">🛡️ Remediation</h2>
            <p>{vuln.get('remediation', 'Remediation steps not provided')}</p>
        </div>
        
        <div class="footer">
            <p><strong>Reported by:</strong> Aether AI Hybrid Edition</p>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity badge."""
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#f59e0b",
            "MEDIUM": "#3b82f6",
            "LOW": "#10b981",
            "INFO": "#6b7280"
        }
        return colors.get(severity, "#6b7280")
    
    def _format_reproduction_steps(self, steps: List[str]) -> str:
        """Format reproduction steps for Markdown."""
        if not steps:
            return "1. Steps not provided"
        
        formatted = []
        for i, step in enumerate(steps, 1):
            formatted.append(f"{i}. {step}")
        
        return "\n".join(formatted)
    
    def _format_reproduction_steps_html(self, steps: List[str]) -> str:
        """Format reproduction steps for HTML."""
        if not steps:
            return "<ol class='steps'><li>Steps not provided</li></ol>"
        
        items = "".join(f"<li>{step}</li>" for step in steps)
        return f"<ol class='steps'>{items}</ol>"
    
    def _format_cvss_breakdown(self, cvss_vector: str) -> str:
        """Format CVSS breakdown."""
        if not cvss_vector:
            return "CVSS vector not provided"
        
        return f"""
- **Vector String**: `{cvss_vector}`
- **Calculator**: https://www.first.org/cvss/calculator/3.1#{cvss_vector}
"""
    
    def _format_evidence(self, evidence: List) -> str:
        """Format evidence list."""
        if not evidence:
            return "No evidence provided"
        
        formatted = []
        for i, item in enumerate(evidence, 1):
            if isinstance(item, str):
                formatted.append(f"{i}. {item}")
            elif isinstance(item, dict):
                desc = item.get("description", "")
                file = item.get("file", "")
                formatted.append(f"{i}. {desc}\n   - File: `{file}`")
        
        return "\n".join(formatted)
    
    def _format_references(self, references: List) -> str:
        """Format reference links."""
        if not references:
            return "No references provided"
        
        formatted = []
        for ref in references:
            if isinstance(ref, str):
                formatted.append(f"- {ref}")
            elif isinstance(ref, dict):
                title = ref.get("title", "Link")
                url = ref.get("url", "")
                formatted.append(f"- [{title}]({url})")
        
        return "\n".join(formatted)
    
    async def generate_cvss_score(
        self,
        attack_vector: str = "NETWORK",
        attack_complexity: str = "LOW",
        privileges_required: str = "NONE",
        user_interaction: str = "NONE",
        scope: str = "UNCHANGED",
        confidentiality: str = "HIGH",
        integrity: str = "HIGH",
        availability: str = "HIGH"
    ) -> Dict:
        """
        Calculate CVSS 3.1 score.
        
        Args:
            attack_vector: NETWORK, ADJACENT, LOCAL, PHYSICAL
            attack_complexity: LOW, HIGH
            privileges_required: NONE, LOW, HIGH
            user_interaction: NONE, REQUIRED
            scope: UNCHANGED, CHANGED
            confidentiality: NONE, LOW, HIGH
            integrity: NONE, LOW, HIGH
            availability: NONE, LOW, HIGH
        
        Returns:
            CVSS score and vector
        """
        # CVSS 3.1 scoring logic (simplified)
        scores = {
            "attack_vector": {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2},
            "attack_complexity": {"LOW": 0.77, "HIGH": 0.44},
            "privileges_required_unchanged": {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27},
            "privileges_required_changed": {"NONE": 0.85, "LOW": 0.68, "HIGH": 0.50},
            "user_interaction": {"NONE": 0.85, "REQUIRED": 0.62},
            "confidentiality": {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56},
            "integrity": {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56},
            "availability": {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}
        }
        
        # Calculate base score (simplified - real CVSS is more complex)
        av_score = scores["attack_vector"].get(attack_vector, 0.85)
        ac_score = scores["attack_complexity"].get(attack_complexity, 0.77)
        
        if scope == "CHANGED":
            pr_score = scores["privileges_required_changed"].get(privileges_required, 0.85)
        else:
            pr_score = scores["privileges_required_unchanged"].get(privileges_required, 0.85)
        
        ui_score = scores["user_interaction"].get(user_interaction, 0.85)
        c_score = scores["confidentiality"].get(confidentiality, 0.56)
        i_score = scores["integrity"].get(integrity, 0.56)
        a_score = scores["availability"].get(availability, 0.56)
        
        # Exploitability sub-score
        exploitability = 8.22 * av_score * ac_score * pr_score * ui_score
        
        # Impact sub-score
        impact = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))
        
        if scope == "UNCHANGED":
            impact_score = 6.42 * impact
        else:
            impact_score = 7.52 * (impact - 0.029) - 3.25 * ((impact - 0.02) ** 15)
        
        # Base score
        if impact_score <= 0:
            base_score = 0.0
        elif scope == "UNCHANGED":
            base_score = min(exploitability + impact_score, 10.0)
        else:
            base_score = min(1.08 * (exploitability + impact_score), 10.0)
        
        base_score = round(base_score, 1)
        
        # Determine severity
        if base_score >= 9.0:
            severity = "CRITICAL"
        elif base_score >= 7.0:
            severity = "HIGH"
        elif base_score >= 4.0:
            severity = "MEDIUM"
        elif base_score > 0:
            severity = "LOW"
        else:
            severity = "NONE"
        
        # Build vector string
        vector = f"CVSS:3.1/AV:{attack_vector[0]}/AC:{attack_complexity[0]}/PR:{privileges_required[0]}/UI:{user_interaction[0]}/S:{scope[0]}/C:{confidentiality[0]}/I:{integrity[0]}/A:{availability[0]}"
        
        return {
            "score": base_score,
            "severity": severity,
            "vector": vector,
            "exploitability": round(exploitability, 2),
            "impact": round(impact_score, 2)
        }


# Global instance
_report_generator = None

def get_report_generator() -> ReportGenerator:
    """Get global report generator instance."""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator
