"""
Security & Bug Bounty API Routes
BurpSuite integration and automated pentesting endpoints
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime

from src.action.security import BurpSuiteIntegration, BugBountyEngine, VulnerabilityAnalyzer
from src.cognitive.llm.model_router import ModelRouter
from src.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/security", tags=["security"])

burp = BurpSuiteIntegration()
model_router = ModelRouter()
analyzer = VulnerabilityAnalyzer(model_router)
bugbounty = BugBountyEngine()


# ==================== REQUEST MODELS ====================

class BurpConfigRequest(BaseModel):
    api_url: str = Field("http://127.0.0.1:1337", description="BurpSuite API URL")
    api_key: Optional[str] = Field(None, description="BurpSuite API key")
    burp_executable: Optional[str] = Field(None, description="Path to Burp Suite jar/exe")


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to scan")
    scan_type: str = Field("active", description="Scan type: active or passive")
    scope_only: bool = Field(True, description="Only scan URLs in scope")


class IntruderRequest(BaseModel):
    url: str = Field(..., description="Target URL (use FUZZ for payload position)")
    payloads: List[str] = Field(..., description="List of payloads to test")
    attack_type: str = Field("sniper", description="Attack type")


class AddScopeRequest(BaseModel):
    url: str = Field(..., description="URL to add to scope")


class AddTargetRequest(BaseModel):
    domain: str = Field(..., description="Target domain")
    scope: List[str] = Field(..., description="In-scope URLs")
    out_of_scope: List[str] = Field(default_factory=list, description="Out-of-scope URLs")
    program_type: str = Field("web", description="Program type")


class VulnAnalysisRequest(BaseModel):
    vulnerability_data: Dict[str, Any] = Field(..., description="Vulnerability data to analyze")
    deep_analysis: bool = Field(True, description="Enable AI-powered deep analysis")


class BugBountyAutomationRequest(BaseModel):
    domain: str = Field(..., description="Target domain")
    output_dir: str = Field("./bug_bounty_results", description="Output directory")


# ==================== BURP SUITE ENDPOINTS ====================

@router.post("/burp/configure")
async def configure_burp(config: BurpConfigRequest):
    """Configure BurpSuite integration"""
    try:
        global burp
        burp = BurpSuiteIntegration(
            api_url=config.api_url,
            api_key=config.api_key,
            burp_executable=config.burp_executable
        )
        
        status = burp.check_burp_status()
        
        return {
            "success": True,
            "message": "BurpSuite configured",
            "status": status
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/burp/status")
async def get_burp_status():
    """Check BurpSuite status"""
    status = burp.check_burp_status()
    return status


@router.post("/burp/start")
async def start_burp(headless: bool = True, project_file: Optional[str] = None):
    """Start BurpSuite programmatically"""
    try:
        success = burp.start_burp(headless=headless, project_file=project_file)
        
        if success:
            return {
                "success": True,
                "message": "BurpSuite started successfully",
                "api_url": burp.api_url
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to start BurpSuite")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/burp/scan")
async def scan_url(request: ScanRequest):
    """Initiate vulnerability scan"""
    try:
        result = burp.scan_url(
            url=request.url,
            scan_type=request.scan_type,
            scope_only=request.scope_only
        )
        
        if result.get("success"):
            return result
        else:
            raise HTTPException(status_code=500, detail=result.get("error"))
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/burp/scan/{task_id}")
async def get_scan_status_endpoint(task_id: str):
    """Get scan status"""
    status = burp.get_scan_status(task_id)
    return status


@router.get("/burp/issues")
async def get_scan_issues(url: Optional[str] = None):
    """Get scan results"""
    issues = burp.get_scan_issues(url)
    
    return {
        "total_issues": len(issues),
        "issues": [
            {
                "url": issue.url,
                "type": issue.vulnerability_type,
                "severity": issue.severity,
                "confidence": issue.confidence,
                "evidence": issue.evidence,
                "remediation": issue.remediation
            }
            for issue in issues
        ]
    }


@router.post("/burp/intruder")
async def run_intruder(request: IntruderRequest):
    """Execute Intruder attack"""
    try:
        results = burp.intruder_attack(
            url=request.url,
            payloads=request.payloads,
            attack_type=request.attack_type
        )
        
        return {
            "total_requests": len(results),
            "interesting_responses": len([r for r in results if r.grep_match]),
            "results": [
                {
                    "payload": r.payload,
                    "status_code": r.status_code,
                    "response_length": r.response_length,
                    "response_time_ms": r.response_time,
                    "interesting": r.grep_match
                }
                for r in results
            ]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/burp/proxy/history")
async def get_proxy_history(filter_url: Optional[str] = None):
    """Get proxy history"""
    history = burp.get_proxy_history(filter_url)
    return {"total_items": len(history), "history": history}


@router.post("/burp/scope")
async def add_to_scope(request: AddScopeRequest):
    """Add URL to Burp scope"""
    success = burp.add_to_scope(request.url)
    
    if success:
        return {"success": True, "message": f"Added {request.url} to scope"}
    else:
        raise HTTPException(status_code=500, detail="Failed to add to scope")


@router.get("/burp/scope")
async def get_scope():
    """Get current scope"""
    scope = burp.get_scope()
    return {"scope": scope}


@router.post("/burp/report")
async def generate_burp_report(
    output_file: str,
    report_type: str = "html",
    include_requests: bool = True
):
    """Generate vulnerability report"""
    try:
        success = burp.generate_report(
            output_file=output_file,
            report_type=report_type,
            include_requests=include_requests
        )
        
        if success:
            return {
                "success": True,
                "message": "Report generated",
                "file": output_file
            }
        else:
            raise HTTPException(status_code=500, detail="Report generation failed")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== AI VULNERABILITY ANALYSIS ====================

@router.post("/analyze/vulnerability")
async def analyze_vulnerability(request: VulnAnalysisRequest):
    """Analyze vulnerability with AI"""
    try:
        result = await analyzer.analyze_vulnerability(
            vuln_data=request.vulnerability_data,
            deep_analysis=request.deep_analysis
        )
        
        return {
            "vulnerability_type": result.vulnerability_type,
            "severity": result.severity,
            "confidence": result.confidence,
            "url": result.url,
            "exploitation_steps": result.exploitation_steps,
            "impact_analysis": result.impact_analysis,
            "remediation": result.remediation,
            "cvss_score": result.cvss_score,
            "cwe_id": result.cwe_id,
            "owasp_category": result.owasp_category,
            "ai_insights": result.ai_insights
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/prioritize")
async def prioritize_vulnerabilities(vulnerabilities: List[Dict[str, Any]]):
    """Prioritize vulnerabilities by risk"""
    try:
        prioritized = await analyzer.prioritize_vulnerabilities(vulnerabilities)
        
        return {
            "total_vulnerabilities": len(prioritized),
            "critical": len([v for v in prioritized if v.severity == "Critical"]),
            "high": len([v for v in prioritized if v.severity == "High"]),
            "medium": len([v for v in prioritized if v.severity == "Medium"]),
            "low": len([v for v in prioritized if v.severity == "Low"]),
            "vulnerabilities": [
                {
                    "type": v.vulnerability_type,
                    "severity": v.severity,
                    "url": v.url,
                    "cvss_score": v.cvss_score
                }
                for v in prioritized
            ]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/exploit-chains")
async def find_exploit_chains(vulnerabilities: List[Dict[str, Any]]):
    """Discover potential exploit chains"""
    try:
        from src.action.security.vuln_analyzer import VulnerabilityReport
        
        vuln_reports = []
        for v in vulnerabilities:
            report = VulnerabilityReport(
                vulnerability_type=v.get('vulnerability_type', 'Unknown'),
                severity=v.get('severity', 'Unknown'),
                confidence=v.get('confidence', 'Unknown'),
                url=v.get('url', ''),
                parameter=v.get('parameter'),
                evidence=v.get('evidence', ''),
                exploitation_steps=[],
                impact_analysis='',
                remediation='',
                cvss_score=None,
                cwe_id=None,
                owasp_category=None
            )
            vuln_reports.append(report)
        
        chains = await analyzer.find_exploit_chains(vuln_reports)
        
        return {
            "exploit_chains_found": len(chains),
            "chains": chains
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== BUG BOUNTY AUTOMATION ====================

@router.post("/bugbounty/target")
async def add_bug_bounty_target(request: AddTargetRequest):
    """Add bug bounty target"""
    success = bugbounty.add_target(
        domain=request.domain,
        scope=request.scope,
        out_of_scope=request.out_of_scope,
        program_type=request.program_type
    )
    
    if success:
        return {
            "success": True,
            "message": f"Target {request.domain} added",
            "scope": request.scope
        }
    else:
        raise HTTPException(status_code=500, detail="Failed to add target")


@router.post("/bugbounty/recon")
async def run_reconnaissance(domain: str):
    """Run reconnaissance on target"""
    try:
        results = await bugbounty.reconnaissance(domain)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bugbounty/scan")
async def run_bug_bounty_scan(domain: str, deep_scan: bool = True):
    """Run automated vulnerability scan"""
    try:
        vulnerabilities = await bugbounty.automated_scan(domain, deep_scan=deep_scan)
        
        return {
            "domain": domain,
            "total_vulnerabilities": len(vulnerabilities),
            "critical": len([v for v in vulnerabilities if v.severity == "Critical"]),
            "high": len([v for v in vulnerabilities if v.severity == "High"]),
            "vulnerabilities": [
                {
                    "type": v.vulnerability_type,
                    "severity": v.severity,
                    "url": v.url,
                    "cvss_score": v.cvss_score
                }
                for v in vulnerabilities[:20]
            ]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bugbounty/automate")
async def full_bug_bounty_automation(
    request: BugBountyAutomationRequest,
    background_tasks: BackgroundTasks
):
    """
    Complete bug bounty automation workflow
    Runs in background
    """
    try:
        async def run_automation():
            await bugbounty.full_automation(
                domain=request.domain,
                output_dir=request.output_dir
            )
        
        background_tasks.add_task(run_automation)
        
        return {
            "success": True,
            "message": f"Bug bounty automation started for {request.domain}",
            "output_dir": request.output_dir,
            "status": "running in background"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/bugbounty/targets")
async def list_targets():
    """List all bug bounty targets"""
    return {
        "total_targets": len(bugbounty.targets),
        "targets": [
            {
                "domain": domain,
                "scope": target.scope,
                "program_type": target.program_type
            }
            for domain, target in bugbounty.targets.items()
        ]
    }


@router.get("/bugbounty/findings")
async def get_all_findings():
    """Get all vulnerability findings"""
    return {
        "total_findings": len(bugbounty.findings),
        "critical": len([f for f in bugbounty.findings if f.severity == "Critical"]),
        "high": len([f for f in bugbounty.findings if f.severity == "High"]),
        "medium": len([f for f in bugbounty.findings if f.severity == "Medium"]),
        "low": len([f for f in bugbounty.findings if f.severity == "Low"]),
        "findings": [
            {
                "type": f.vulnerability_type,
                "severity": f.severity,
                "url": f.url,
                "cvss_score": f.cvss_score,
                "cwe_id": f.cwe_id
            }
            for f in bugbounty.findings
        ]
    }


# ==================== UTILITIES ====================

@router.get("/status")
async def get_security_status():
    """Get overall security module status"""
    burp_status = burp.check_burp_status()
    
    return {
        "burp_suite": burp_status,
        "ai_analyzer": "active",
        "bug_bounty_engine": "active",
        "active_targets": len(bugbounty.targets),
        "total_findings": len(bugbounty.findings)
    }


@router.get("/payloads/{payload_type}")
async def get_payloads(payload_type: str, count: int = 50):
    """Get AI-generated security payloads"""
    try:
        prompt = f"Generate {count} creative {payload_type} payloads for security testing. Return as JSON array of strings."
        
        messages = [{"role": "user", "content": prompt}]
        response = await model_router.route_request(messages=messages)
        
        if response:
            import json
            try:
                payloads = json.loads(response.content)
                return {"payload_type": payload_type, "count": len(payloads), "payloads": payloads}
            except:
                return {"payload_type": payload_type, "payloads": response.content.split('\n')}
        
        return {"payload_type": payload_type, "payloads": []}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
