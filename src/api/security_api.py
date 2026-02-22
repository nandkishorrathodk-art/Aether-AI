"""
Security API Endpoints for Bug Bounty Hunting
Integrates CVE database, Nuclei scanner, AI scanner, and report generator
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict

from src.utils.logger import get_logger
from src.security.cve_database import get_cve_database
from src.security.nuclei_scanner import get_nuclei_scanner
from src.security.ai_vulnerability_scanner import get_ai_vulnerability_scanner
from src.security.report_generator import get_report_generator

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/security", tags=["security"])


class CVESearchRequest(BaseModel):
    query: str = Field(..., description="Search query")
    max_results: int = Field(50, description="Maximum results")
    min_severity: str = Field("LOW", description="Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)")


class NucleiScanRequest(BaseModel):
    target: str = Field(..., description="Target URL or domain")
    severity: Optional[List[str]] = Field(None, description="Filter by severity")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    rate_limit: int = Field(150, description="Requests per second")


class HTTPTrafficRequest(BaseModel):
    request: Dict = Field(..., description="HTTP request dict")
    response: Dict = Field(..., description="HTTP response dict")


class ReportRequest(BaseModel):
    vulnerability: Dict = Field(..., description="Vulnerability details")
    target: str = Field(..., description="Target URL/domain")
    format: str = Field("markdown", description="Report format (markdown, html, json)")


@router.get("/cve/search")
async def search_cves(
    query: str,
    max_results: int = 50,
    min_severity: str = "LOW"
):
    """
    Search CVE database by keyword.
    
    **Example**: `/api/v1/security/cve/search?query=apache&min_severity=HIGH`
    
    **Returns**: List of matching CVEs with scores and descriptions
    """
    try:
        cve_db = await get_cve_database()
        results = await cve_db.search(query, max_results, min_severity)
        
        return {
            "success": True,
            "query": query,
            "count": len(results),
            "cves": results
        }
    
    except Exception as e:
        logger.error(f"CVE search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cve/{cve_id}")
async def get_cve_details(cve_id: str):
    """
    Get detailed information about specific CVE.
    
    **Example**: `/api/v1/security/cve/CVE-2021-44228`
    
    **Returns**: Complete CVE information including CVSS, references, affected products
    """
    try:
        cve_db = await get_cve_database()
        cve = await cve_db.get_by_id(cve_id)
        
        if not cve:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        
        return {
            "success": True,
            "cve": cve
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CVE details error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cve/product/{product_name}")
async def search_cves_by_product(
    product_name: str,
    max_results: int = 50
):
    """
    Search CVEs affecting specific product.
    
    **Example**: `/api/v1/security/cve/product/nginx`
    
    **Returns**: CVEs affecting the specified product
    """
    try:
        cve_db = await get_cve_database()
        results = await cve_db.search_by_product(product_name, max_results)
        
        return {
            "success": True,
            "product": product_name,
            "count": len(results),
            "cves": results
        }
    
    except Exception as e:
        logger.error(f"Product CVE search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cve/stats")
async def get_cve_statistics():
    """
    Get CVE database statistics.
    
    **Returns**: Total CVEs, severity breakdown, last update time
    """
    try:
        cve_db = await get_cve_database()
        stats = await cve_db.get_statistics()
        
        return {
            "success": True,
            **stats
        }
    
    except Exception as e:
        logger.error(f"CVE stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cve/update")
async def update_cve_database(
    background_tasks: BackgroundTasks,
    days_back: int = 30
):
    """
    Update CVE database with recent entries.
    
    **Note**: This runs in background and may take several minutes
    
    **Returns**: Confirmation that update started
    """
    try:
        async def update_task():
            cve_db = await get_cve_database()
            await cve_db.update_database(days_back)
        
        background_tasks.add_task(update_task)
        
        return {
            "success": True,
            "message": f"CVE database update started (fetching last {days_back} days)",
            "status": "running"
        }
    
    except Exception as e:
        logger.error(f"CVE update error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nuclei/scan")
async def nuclei_scan(request: NucleiScanRequest):
    """
    Scan target with Nuclei vulnerability scanner.
    
    **Requires**: Nuclei binary installed (go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)
    
    **Returns**: Scan results with detected vulnerabilities
    """
    try:
        scanner = await get_nuclei_scanner()
        
        # Check if Nuclei is installed
        if not await scanner.check_installation():
            raise HTTPException(
                status_code=503,
                detail="Nuclei not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
        
        # Run scan
        results = await scanner.scan_target(
            target=request.target,
            severity=request.severity,
            tags=request.tags,
            rate_limit=request.rate_limit
        )
        
        return results
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Nuclei scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nuclei/update-templates")
async def update_nuclei_templates():
    """
    Update Nuclei templates to latest version.
    
    **Returns**: Update status
    """
    try:
        scanner = await get_nuclei_scanner()
        success = await scanner.update_templates()
        
        if success:
            return {
                "success": True,
                "message": "Nuclei templates updated successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Template update failed")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Template update error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nuclei/tags")
async def get_nuclei_tags():
    """
    Get available Nuclei template tags.
    
    **Returns**: List of tags for filtering scans
    """
    try:
        scanner = await get_nuclei_scanner()
        tags = await scanner.get_available_tags()
        
        return {
            "success": True,
            "tags": tags,
            "count": len(tags)
        }
    
    except Exception as e:
        logger.error(f"Tags retrieval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai-scan/analyze-traffic")
async def analyze_http_traffic(request: HTTPTrafficRequest):
    """
    Analyze HTTP traffic with AI for vulnerabilities.
    
    **Uses**: Pattern matching + LLM analysis for high accuracy
    
    **Returns**: Detected vulnerabilities with severity and confidence scores
    """
    try:
        scanner = await get_ai_vulnerability_scanner()
        
        results = await scanner.analyze_http_traffic(
            request=request.request,
            response=request.response
        )
        
        return results
    
    except Exception as e:
        logger.error(f"AI scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai-scan/quick-scan")
async def quick_scan_url(url: str):
    """
    Quick vulnerability scan of a URL.
    
    **Example**: `/api/v1/security/ai-scan/quick-scan?url=https://example.com`
    
    **Returns**: Quick analysis of URL for common vulnerabilities
    """
    try:
        scanner = await get_ai_vulnerability_scanner()
        results = await scanner.scan_url(url)
        
        return results
    
    except Exception as e:
        logger.error(f"Quick scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/report/generate")
async def generate_report(request: ReportRequest):
    """
    Generate professional bug bounty report.
    
    **Formats**: markdown, html, json
    
    **Returns**: Path to generated report file
    """
    try:
        generator = get_report_generator()
        
        file_path = await generator.generate_bug_bounty_report(
            vulnerability=request.vulnerability,
            target=request.target,
            format=request.format
        )
        
        return {
            "success": True,
            "report_path": file_path,
            "format": request.format
        }
    
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/report/cvss-score")
async def calculate_cvss(
    attack_vector: str = "NETWORK",
    attack_complexity: str = "LOW",
    privileges_required: str = "NONE",
    user_interaction: str = "NONE",
    scope: str = "UNCHANGED",
    confidentiality: str = "HIGH",
    integrity: str = "HIGH",
    availability: str = "HIGH"
):
    """
    Calculate CVSS 3.1 score for vulnerability.
    
    **Returns**: CVSS score, severity, and vector string
    """
    try:
        generator = get_report_generator()
        
        score = await generator.generate_cvss_score(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability
        )
        
        return {
            "success": True,
            **score
        }
    
    except Exception as e:
        logger.error(f"CVSS calculation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
