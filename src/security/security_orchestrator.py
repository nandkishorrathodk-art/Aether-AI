"""
Security Testing Orchestrator
Coordinates all security tools for comprehensive testing
"""

import asyncio
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime

from .vulnerability_database import VulnerabilityDatabase
from .tool_integrations import SecurityToolOrchestrator, ScanTool
from .ai_scanner import AIVulnerabilityScanner
from .threat_intelligence import ThreatIntelligencePlatform
from .report_generator import SecurityReportGenerator
from .cloud_scanner import CloudSecurityScanner, CloudPlatform

logger = logging.getLogger(__name__)


class AetherSecurityOrchestrator:
    """
    Master security orchestrator for Aether AI
    
    Coordinates:
    - Vulnerability database
    - Security tool integrations (Metasploit, Nessus, ZAP, Nuclei)
    - AI-powered scanning
    - Threat intelligence
    - Report generation
    - Cloud/container scanning
    """
    
    def __init__(self):
        """Initialize security orchestrator"""
        self.vuln_db = VulnerabilityDatabase()
        self.tool_orchestrator = SecurityToolOrchestrator()
        self.ai_scanner = AIVulnerabilityScanner()
        self.threat_intel = ThreatIntelligencePlatform()
        self.report_gen = SecurityReportGenerator()
        self.cloud_scanner = CloudSecurityScanner()
        
        logger.info("🛡️ Aether Security Orchestrator initialized - Full suite ready")
    
    async def comprehensive_scan(
        self,
        target: str,
        scan_profile: str = "full"
    ) -> Dict[str, Any]:
        """
        Perform comprehensive security scan
        
        Args:
            target: Target URL or system
            scan_profile: Scan profile (quick, standard, full, deep)
        
        Returns:
            Comprehensive scan results
        """
        logger.info(f"🔍 Starting comprehensive scan: {target} (profile: {scan_profile})")
        
        scan_results = {
            "target": target,
            "scan_profile": scan_profile,
            "started_at": datetime.now().isoformat(),
            "vulnerabilities": [],
            "threat_intelligence": {},
            "ai_findings": [],
            "tool_results": {}
        }
        
        if scan_profile == "quick":
            tools = [ScanTool.NUCLEI]
        elif scan_profile == "standard":
            tools = [ScanTool.ZAP, ScanTool.NUCLEI]
        elif scan_profile == "full":
            tools = [ScanTool.ZAP, ScanTool.NUCLEI, ScanTool.NESSUS]
        else:
            tools = [ScanTool.ZAP, ScanTool.NUCLEI, ScanTool.NESSUS, ScanTool.METASPLOIT]
        
        tool_scan = await self.tool_orchestrator.orchestrated_scan(
            target=target,
            tools=tools,
            parallel=True
        )
        scan_results["tool_results"] = tool_scan
        
        for tool_name, result in tool_scan.items():
            if isinstance(result, dict) and "findings" in result:
                scan_results["vulnerabilities"].extend(result["findings"])
        
        logger.info("🤖 Running AI-powered analysis...")
        ai_findings = await self.ai_scanner.scan_application(
            base_url=target,
            endpoints=["/", "/api", "/admin"]
        )
        scan_results["ai_findings"] = ai_findings.get("detections", [])
        
        logger.info("🌐 Enriching with threat intelligence...")
        for vuln in scan_results["vulnerabilities"]:
            if "cve_id" in vuln:
                enriched = await self.threat_intel.enrich_vulnerability(vuln)
                vuln.update(enriched.get("threat_intelligence", {}))
        
        scan_results["completed_at"] = datetime.now().isoformat()
        scan_results["total_vulnerabilities"] = len(scan_results["vulnerabilities"])
        
        logger.info(f"✅ Scan complete: {scan_results['total_vulnerabilities']} vulnerabilities found")
        
        return scan_results
    
    async def bug_bounty_scan(
        self,
        target: str,
        program_name: str = "Unknown"
    ) -> Dict[str, Any]:
        """
        Specialized scan for bug bounty programs
        
        Args:
            target: Target URL
            program_name: Bug bounty program name
        
        Returns:
            Bug bounty scan results with prioritized findings
        """
        logger.info(f"🎯 Starting bug bounty scan: {program_name} - {target}")
        
        scan_results = await self.comprehensive_scan(target, scan_profile="full")
        
        high_value_vulns = [
            v for v in scan_results["vulnerabilities"]
            if v.get("severity") in ["CRITICAL", "HIGH"]
        ]
        
        report_path = self.report_gen.generate_comprehensive_report(
            scan_results=scan_results,
            output_format="html"
        )
        
        return {
            "program": program_name,
            "target": target,
            "total_findings": len(scan_results["vulnerabilities"]),
            "high_value_findings": len(high_value_vulns),
            "top_vulnerabilities": high_value_vulns[:5],
            "report_path": report_path,
            "scan_data": scan_results
        }
    
    async def cloud_security_audit(
        self,
        platform: CloudPlatform,
        resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform cloud security audit
        
        Args:
            platform: Cloud platform
            resource_id: Specific resource to scan
        
        Returns:
            Cloud security audit results
        """
        logger.info(f"☁️ Starting cloud security audit: {platform.value}")
        
        if platform == CloudPlatform.DOCKER and resource_id:
            results = await self.cloud_scanner.scan_docker_image(resource_id)
        elif platform == CloudPlatform.KUBERNETES:
            results = await self.cloud_scanner.scan_kubernetes_cluster()
        elif platform == CloudPlatform.AWS:
            results = await self.cloud_scanner.scan_aws_security()
        else:
            results = {"error": f"Unsupported platform: {platform.value}"}
        
        recommendations = self.cloud_scanner.get_recommendations(platform)
        results["recommendations"] = recommendations
        
        return results
    
    async def update_intelligence(self):
        """Update vulnerability database and threat intelligence"""
        logger.info("📥 Updating vulnerability database and threat feeds...")
        
        await self.threat_intel.update_feeds()
        
        logger.info("✅ Intelligence updated")
    
    def generate_report(
        self,
        scan_results: Dict[str, Any],
        output_format: str = "html"
    ) -> str:
        """
        Generate security report
        
        Args:
            scan_results: Scan results
            output_format: Output format (html, json, markdown)
        
        Returns:
            Path to generated report
        """
        return self.report_gen.generate_comprehensive_report(
            scan_results=scan_results,
            output_format=output_format
        )
    
    async def vulnerability_lookup(
        self,
        cve_id: str = None,
        keyword: str = None
    ) -> Dict[str, Any]:
        """
        Look up vulnerability information
        
        Args:
            cve_id: CVE identifier
            keyword: Search keyword
        
        Returns:
            Vulnerability information
        """
        if cve_id:
            cve_info = await self.vuln_db.get_cve_details(cve_id)
            threat_info = self.threat_intel.check_indicator("cve", cve_id)
            
            return {
                "cve": cve_info,
                "threat_intelligence": threat_info.to_dict() if threat_info else None
            }
        elif keyword:
            results = await self.vuln_db.search_vulnerabilities(keyword=keyword, limit=10)
            return {
                "keyword": keyword,
                "results": results
            }
        
        return {"error": "Provide either cve_id or keyword"}
    
    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        vuln_stats = self.vuln_db.get_statistics()
        threat_stats = self.threat_intel.get_statistics()
        
        return {
            "status": "operational",
            "components": {
                "vulnerability_database": {
                    "status": "ready",
                    "cve_count": vuln_stats.get("total_cves", 0)
                },
                "threat_intelligence": {
                    "status": "ready",
                    "indicators": threat_stats.get("total_indicators", 0)
                },
                "security_tools": {
                    "status": "ready",
                    "tools_available": len(self.tool_orchestrator.integrations)
                },
                "ai_scanner": {
                    "status": "ready"
                },
                "cloud_scanner": {
                    "status": "ready",
                    "platforms": ["docker", "kubernetes", "aws"]
                }
            },
            "capabilities": [
                "Web Application Scanning",
                "API Security Testing",
                "Cloud Security Auditing",
                "Container Vulnerability Scanning",
                "AI-Powered Detection",
                "Threat Intelligence Integration",
                "Automated Report Generation"
            ]
        }


orchestrator = AetherSecurityOrchestrator()
