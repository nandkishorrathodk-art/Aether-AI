"""
Bug Bounty API Routes

API endpoints for automated bug bounty hunting with BurpSuite integration.
Includes reconnaissance, scanning, vulnerability analysis, and report generation.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, Field, HttpUrl
from typing import List, Dict, Optional, Any
from datetime import datetime
import asyncio

from src.security.bugbounty.burp_integration import (
    BurpSuiteClient, ScanConfig, ScanType
)
from src.security.bugbounty.recon_engine import ReconEngine, Target
from src.security.bugbounty.vulnerability_analyzer import (
    VulnerabilityAnalyzer, Vulnerability, Severity
)
from src.security.bugbounty.exploit_generator import ExploitGenerator, ExploitType
from src.security.bugbounty.report_generator import (
    ReportGenerator, BugReport, Platform, ReportFormat
)
from src.security.bugbounty.scope_validator import (
    ScopeValidator, ScopeManager, Program
)

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/bugbounty", tags=["Bug Bounty"])

# Global instances
burp_client = None
recon_engine = ReconEngine()
vuln_analyzer = VulnerabilityAnalyzer()
exploit_generator = ExploitGenerator()
report_generator = ReportGenerator()
scope_manager = ScopeManager()

# In-memory storage (in production, use database)
active_scans: Dict[str, Dict] = {}
targets: Dict[str, Target] = {}
vulnerabilities: Dict[str, List[Vulnerability]] = {}


# Request/Response Models

class ProgramCreate(BaseModel):
    name: str
    platform: str = "Custom"
    in_scope: List[str]
    out_of_scope: List[str] = []
    no_dos: bool = True
    no_social_engineering: bool = True


class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "CrawlAndAudit"
    crawl_depth: int = 5
    check_scope: bool = True


class ReconRequest(BaseModel):
    domain: str
    program_name: str
    scope: List[str] = []
    passive_only: bool = False


class VulnAnalysisRequest(BaseModel):
    scan_id: str
    filter_false_positives: bool = True


class ExploitRequest(BaseModel):
    vulnerability_id: str
    exploit_type: str = "POC"


class ReportRequest(BaseModel):
    vulnerability_ids: List[str]
    format: str = "markdown"
    platform: str = "Custom"


# Routes

@router.post("/configure")
async def configure_burpsuite(
    api_url: str = "http://localhost:1337",
    api_key: Optional[str] = None
):
    """Configure BurpSuite connection"""
    global burp_client
    
    try:
        burp_client = BurpSuiteClient(api_url=api_url, api_key=api_key)
        version = burp_client.get_version()
        
        return {
            "status": "configured",
            "burp_version": version,
            "api_url": api_url
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"BurpSuite connection failed: {str(e)}")


@router.post("/programs")
async def create_program(program: ProgramCreate):
    """Create bug bounty program configuration"""
    prog = Program(
        name=program.name,
        platform=program.platform,
        in_scope=program.in_scope,
        out_of_scope=program.out_of_scope,
        no_dos=program.no_dos,
        no_social_engineering=program.no_social_engineering
    )
    
    scope_manager.add_program(prog)
    scope_manager.set_active_program(program.name)
    
    validator = scope_manager.get_validator(program.name)
    
    return {
        "program": program.name,
        "status": "created",
        "scope_summary": validator.get_scope_summary(),
        "warning": validator.generate_scope_warning()
    }


@router.get("/programs")
async def list_programs():
    """List all configured programs"""
    programs = scope_manager.list_programs()
    
    return {
        "programs": programs,
        "active": scope_manager.active_program
    }


@router.post("/recon")
async def start_reconnaissance(
    request: ReconRequest,
    background_tasks: BackgroundTasks
):
    """Start reconnaissance on target domain"""
    
    # Validate scope
    validator = scope_manager.get_validator()
    if validator.program:
        scope_check = validator.validate_url(f"https://{request.domain}")
        if not scope_check["in_scope"]:
            raise HTTPException(
                status_code=403,
                detail="Target is OUT OF SCOPE. Cannot proceed."
            )
    
    # Create target
    target = Target(
        domain=request.domain,
        program_name=request.program_name,
        scope=request.scope
    )
    
    target_id = f"recon_{request.domain}_{int(datetime.now().timestamp())}"
    targets[target_id] = target
    
    # Run recon in background
    async def run_recon():
        try:
            await recon_engine.run_full_recon(target)
            logger.info(f"Reconnaissance complete for {request.domain}")
        except Exception as e:
            logger.error(f"Reconnaissance failed: {e}")
    
    background_tasks.add_task(run_recon)
    
    return {
        "target_id": target_id,
        "status": "started",
        "domain": request.domain,
        "message": "Reconnaissance started in background"
    }


@router.get("/recon/{target_id}")
async def get_recon_results(target_id: str):
    """Get reconnaissance results"""
    if target_id not in targets:
        raise HTTPException(status_code=404, detail="Target not found")
    
    target = targets[target_id]
    
    return {
        "target_id": target_id,
        "domain": target.domain,
        "subdomains": list(target.subdomains)[:100],  # Limit for response size
        "subdomains_count": len(target.subdomains),
        "ip_addresses": list(target.ip_addresses),
        "urls_count": len(target.urls),
        "technologies": target.technologies,
        "open_ports": target.open_ports,
        "last_updated": target.last_updated.isoformat()
    }


@router.post("/scan")
async def start_scan(request: ScanRequest):
    """Start BurpSuite scan"""
    if not burp_client:
        raise HTTPException(
            status_code=400,
            detail="BurpSuite not configured. Call /configure first."
        )
    
    # Validate scope
    if request.check_scope:
        validator = scope_manager.get_validator()
        if validator.program:
            scope_check = validator.validate_url(request.target_url)
            if not scope_check["in_scope"]:
                raise HTTPException(
                    status_code=403,
                    detail=f"Target is OUT OF SCOPE: {scope_check['warnings']}"
                )
    
    try:
        # Create scan config
        config = ScanConfig(
            urls=[request.target_url],
            scan_type=ScanType[request.scan_type.upper()],
            crawl_depth=request.crawl_depth
        )
        
        # Start scan
        scan_id = burp_client.start_scan(config)
        
        # Store scan info
        active_scans[scan_id] = {
            "url": request.target_url,
            "started_at": datetime.now().isoformat(),
            "status": "running"
        }
        
        return {
            "scan_id": scan_id,
            "status": "started",
            "target_url": request.target_url
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if not burp_client:
        raise HTTPException(status_code=400, detail="BurpSuite not configured")
    
    try:
        status = burp_client.get_scan_status(scan_id)
        
        # Update stored status
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = status.get("scan_status")
        
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")


@router.get("/scan/{scan_id}/issues")
async def get_scan_issues(scan_id: str):
    """Get vulnerabilities found in scan"""
    if not burp_client:
        raise HTTPException(status_code=400, detail="BurpSuite not configured")
    
    try:
        issues = burp_client.get_scan_issues(scan_id)
        
        # Parse into Vulnerability objects
        vulns = [vuln_analyzer.parse_burp_issue(issue) for issue in issues]
        
        # Store vulnerabilities
        vulnerabilities[scan_id] = vulns
        
        # Analyze
        analysis = vuln_analyzer.analyze_vulnerabilities(vulns)
        
        return {
            "scan_id": scan_id,
            "issues_count": len(issues),
            "vulnerabilities": [v.to_dict() for v in vulns],
            "analysis": analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get issues: {str(e)}")


@router.post("/analyze")
async def analyze_vulnerabilities(request: VulnAnalysisRequest):
    """Analyze scan vulnerabilities with AI"""
    if request.scan_id not in vulnerabilities:
        raise HTTPException(status_code=404, detail="Scan not found or no vulnerabilities")
    
    vulns = vulnerabilities[request.scan_id]
    
    # Filter false positives
    if request.filter_false_positives:
        vulns = vuln_analyzer.filter_false_positives(vulns)
    
    # Analyze
    analysis = vuln_analyzer.analyze_vulnerabilities(vulns)
    
    # AI analysis for critical/high severity
    critical_high = [v for v in vulns if v.severity in [Severity.CRITICAL, Severity.HIGH]]
    
    ai_analyses = []
    if critical_high and vuln_analyzer.ai_client:
        for vuln in critical_high[:5]:  # Limit to 5
            try:
                ai_analysis = await vuln_analyzer.ai_analyze_vulnerability(vuln)
                ai_analyses.append(ai_analysis)
            except:
                pass
    
    return {
        "scan_id": request.scan_id,
        "total_vulnerabilities": len(vulns),
        "analysis": analysis,
        "ai_insights": ai_analyses
    }


@router.post("/exploit")
async def generate_exploit(request: ExploitRequest):
    """Generate exploit for vulnerability"""
    # Find vulnerability
    vuln = None
    for scan_vulns in vulnerabilities.values():
        for v in scan_vulns:
            if v.title == request.vulnerability_id:
                vuln = v
                break
    
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    try:
        # Generate exploit based on type
        if "xss" in vuln.vuln_type.value.lower():
            exploit = exploit_generator.generate_xss_exploit(
                url=vuln.url,
                parameter=vuln.parameter or "q"
            )
        elif "sql" in vuln.vuln_type.value.lower():
            exploit = exploit_generator.generate_sqli_exploit(
                url=vuln.url,
                parameter=vuln.parameter or "id"
            )
        elif "lfi" in vuln.vuln_type.value.lower():
            exploit = exploit_generator.generate_lfi_exploit(
                url=vuln.url,
                parameter=vuln.parameter or "file"
            )
        else:
            # Use AI to generate
            if exploit_generator.ai_client:
                exploit = await exploit_generator.ai_generate_exploit(
                    vulnerability=vuln.to_dict(),
                    target_info={"url": vuln.url}
                )
            else:
                raise HTTPException(
                    status_code=400,
                    detail="No template for this vulnerability type. AI client needed."
                )
        
        return {
            "vulnerability": vuln.title,
            "exploit": exploit.to_dict()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Exploit generation failed: {str(e)}")


@router.post("/report")
async def generate_report(request: ReportRequest):
    """Generate bug bounty report"""
    # Find vulnerabilities
    selected_vulns = []
    for scan_vulns in vulnerabilities.values():
        for v in scan_vulns:
            if v.title in request.vulnerability_ids:
                selected_vulns.append(v)
    
    if not selected_vulns:
        raise HTTPException(status_code=404, detail="No vulnerabilities found")
    
    # Use first vulnerability for report (or combine if multiple)
    vuln = selected_vulns[0]
    
    # Create report
    report = BugReport(
        title=vuln.title,
        vulnerability_type=vuln.vuln_type.value,
        severity=vuln.severity.value,
        url=vuln.url,
        description=vuln.description,
        impact=vuln.impact,
        remediation=vuln.remediation,
        proof_of_concept=vuln.poc,
        cvss_score=vuln.cvss_score,
        cwe_id=vuln.cwe_id,
        platform=Platform[request.platform.upper()]
    )
    
    # Enhance with AI
    if report_generator.ai_client:
        report = await report_generator.ai_enhance_report(report)
    
    # Generate in requested format
    format_enum = ReportFormat[request.format.upper()]
    
    if format_enum == ReportFormat.MARKDOWN:
        content = report_generator.generate_markdown(report)
    elif format_enum == ReportFormat.HTML:
        content = report_generator.generate_html(report)
    elif format_enum == ReportFormat.JSON:
        content = report_generator.generate_json(report)
    else:
        content = report_generator.generate_markdown(report)
    
    return {
        "report": content,
        "format": request.format,
        "platform": request.platform,
        "estimated_bounty": report.estimated_bounty
    }


@router.get("/stats")
async def get_statistics():
    """Get bug bounty hunting statistics"""
    total_vulns = sum(len(vulns) for vulns in vulnerabilities.values())
    
    severity_counts = {}
    type_counts = {}
    
    for vulns in vulnerabilities.values():
        for v in vulns:
            severity = v.severity.value
            vuln_type = v.vuln_type.value
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
    
    return {
        "active_scans": len(active_scans),
        "total_targets": len(targets),
        "total_vulnerabilities": total_vulns,
        "by_severity": severity_counts,
        "by_type": type_counts,
        "programs": len(scope_manager.programs)
    }


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete scan and associated data"""
    if burp_client:
        try:
            burp_client.delete_scan(scan_id)
        except:
            pass
    
    if scan_id in active_scans:
        del active_scans[scan_id]
    
    if scan_id in vulnerabilities:
        del vulnerabilities[scan_id]
    
    return {"status": "deleted", "scan_id": scan_id}


@router.get("/health")
async def health_check():
    """Check if bug bounty services are available"""
    burp_available = False
    burp_version = None
    
    if burp_client:
        try:
            burp_version = burp_client.get_version()
            burp_available = True
        except:
            pass
    
    return {
        "status": "online",
        "burpsuite_configured": burp_client is not None,
        "burpsuite_available": burp_available,
        "burpsuite_version": burp_version,
        "active_scans": len(active_scans),
        "programs_configured": len(scope_manager.programs)
    }
