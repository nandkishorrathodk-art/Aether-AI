"""
Bug Bounty Autopilot API Routes

API endpoints for automated bug hunting with Auto Hunter.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Optional, Any
from datetime import datetime

from src.bugbounty.auto_hunter import AutoHunter
from src.bugbounty.models import ScanStatus, VulnerabilitySeverity
from src.bugbounty.auto_submitter import AutoSubmitter
from src.security.bugbounty.scope_validator import ScopeValidator, Program
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/bugbounty/auto", tags=["Bug Bounty Autopilot"])

auto_hunter = AutoHunter()
auto_submitter = AutoSubmitter()

programs: Dict[str, ScopeValidator] = {}


class AutoHuntRequest(BaseModel):
    target_url: str
    program: str = "general"
    program_scope: Optional[List[str]] = None
    auto_poc: bool = True
    auto_report: bool = True
    report_formats: List[str] = ["markdown", "html", "json"]


class ProgramConfigRequest(BaseModel):
    name: str
    platform: str = "Custom"
    in_scope: List[str]
    out_of_scope: List[str] = []


class HuntResponse(BaseModel):
    hunt_id: str
    status: str
    message: str


@router.post("/start", response_model=HuntResponse)
async def start_auto_hunt(
    request: AutoHuntRequest,
    background_tasks: BackgroundTasks
):
    """
    Start automated bug hunting session
    
    This will:
    1. Detect Burp Suite
    2. Validate target scope (if program configured)
    3. Run automated scan
    4. Analyze vulnerabilities
    5. Generate PoCs for critical/high findings
    6. Generate professional reports
    
    Returns:
        hunt_id for tracking progress
    """
    try:
        scope_validator = None
        
        if request.program_scope:
            temp_program = Program(
                name=request.program,
                platform="Custom",
                in_scope=request.program_scope,
                out_of_scope=[]
            )
            scope_validator = ScopeValidator(temp_program)
        elif request.program in programs:
            scope_validator = programs[request.program]
        
        async def run_hunt():
            try:
                result = await auto_hunter.start_auto_hunt(
                    target_url=request.target_url,
                    program=request.program,
                    scope_validator=scope_validator,
                    auto_poc=request.auto_poc,
                    auto_report=request.auto_report,
                    report_formats=request.report_formats
                )
                
                if result.status == ScanStatus.COMPLETED:
                    logger.info(f"Hunt completed: {result.total_issues_found} findings")
                else:
                    logger.error(f"Hunt failed: {result.error_message}")
                    
            except Exception as e:
                logger.error(f"Hunt execution failed: {e}", exc_info=True)
        
        background_tasks.add_task(run_hunt)
        
        hunt_id = f"hunt_{int(datetime.now().timestamp())}"
        
        return HuntResponse(
            hunt_id=hunt_id,
            status="started",
            message=f"Automated bug hunting started for {request.target_url}"
        )
        
    except Exception as e:
        logger.error(f"Failed to start hunt: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop/{hunt_id}")
async def stop_hunt(hunt_id: str):
    """Stop active hunt"""
    success = await auto_hunter.stop_hunt(hunt_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Hunt not found or already stopped")
    
    return {"status": "stopped", "hunt_id": hunt_id}


@router.post("/pause/{hunt_id}")
async def pause_hunt(hunt_id: str):
    """Pause active hunt"""
    success = await auto_hunter.pause_hunt(hunt_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Hunt not found or cannot be paused")
    
    return {"status": "paused", "hunt_id": hunt_id}


@router.post("/resume/{hunt_id}")
async def resume_hunt(hunt_id: str):
    """Resume paused hunt"""
    success = await auto_hunter.resume_hunt(hunt_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Hunt not found or cannot be resumed")
    
    return {"status": "resumed", "hunt_id": hunt_id}


@router.get("/status")
async def get_autopilot_status():
    """
    Get Bug Bounty Autopilot status
    
    Returns:
        - Burp Suite connectivity
        - Active hunts
        - System status
    """
    burp_info = auto_hunter.burp.get_burp_info()
    active_hunts = auto_hunter.get_active_hunts()
    
    return {
        "autopilot_enabled": True,
        "burp_suite": burp_info,
        "active_hunts": len(active_hunts),
        "hunts": [
            {
                "hunt_id": hunt_id,
                "target": result.target_url,
                "status": result.status.value,
                "vulnerabilities_found": result.total_issues_found,
                "reports_generated": len(result.reports_generated)
            }
            for hunt_id, result in active_hunts.items()
        ]
    }


@router.get("/findings/{hunt_id}")
async def get_hunt_findings(hunt_id: str):
    """
    Get findings from completed hunt
    
    Returns detailed vulnerability information and generated reports.
    """
    result = auto_hunter.get_hunt_result(hunt_id)
    
    if not result:
        raise HTTPException(status_code=404, detail="Hunt not found")
    
    return {
        "hunt_id": hunt_id,
        "target_url": result.target_url,
        "status": result.status.value,
        "scan_started_at": result.scan_started_at.isoformat() if result.scan_started_at else None,
        "scan_completed_at": result.scan_completed_at.isoformat() if result.scan_completed_at else None,
        "total_issues": result.total_issues_found,
        "severity_breakdown": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count
        },
        "vulnerabilities": [v.to_dict() for v in result.vulnerabilities],
        "reports_generated": len(result.reports_generated),
        "estimated_total_payout": result.estimated_total_payout,
        "error_message": result.error_message
    }


@router.get("/summary/{hunt_id}")
async def get_hunt_summary(hunt_id: str):
    """
    Get human-readable summary of hunt results
    """
    result = auto_hunter.get_hunt_result(hunt_id)
    
    if not result:
        raise HTTPException(status_code=404, detail="Hunt not found")
    
    summary = auto_hunter.generate_summary(result)
    
    return {
        "hunt_id": hunt_id,
        "summary": summary,
        "status": result.status.value
    }


@router.post("/programs")
async def configure_program(config: ProgramConfigRequest):
    """
    Configure bug bounty program scope
    
    This defines in-scope and out-of-scope targets for validation.
    """
    program = Program(
        name=config.name,
        platform=config.platform,
        in_scope=config.in_scope,
        out_of_scope=config.out_of_scope
    )
    
    validator = ScopeValidator(program)
    programs[config.name] = validator
    
    logger.info(f"Configured program: {config.name}")
    
    return {
        "status": "configured",
        "program": config.name,
        "in_scope_count": len(config.in_scope),
        "out_of_scope_count": len(config.out_of_scope),
        "scope_summary": validator.get_scope_summary()
    }


@router.get("/programs")
async def list_programs():
    """List all configured programs"""
    return {
        "programs": [
            {
                "name": name,
                "in_scope_count": len(validator.program.in_scope) if validator.program else 0,
                "out_of_scope_count": len(validator.program.out_of_scope) if validator.program else 0
            }
            for name, validator in programs.items()
        ]
    }


@router.delete("/programs/{program_name}")
async def delete_program(program_name: str):
    """Delete program configuration"""
    if program_name not in programs:
        raise HTTPException(status_code=404, detail="Program not found")
    
    del programs[program_name]
    
    return {"status": "deleted", "program": program_name}


@router.post("/generate-report/{hunt_id}")
async def generate_additional_report(
    hunt_id: str,
    formats: List[str] = ["markdown", "html", "json"]
):
    """
    Generate additional reports for a completed hunt
    
    Useful if you want to regenerate reports in different formats.
    """
    result = auto_hunter.get_hunt_result(hunt_id)
    
    if not result:
        raise HTTPException(status_code=404, detail="Hunt not found")
    
    if result.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Hunt not completed yet. Current status: {result.status.value}"
        )
    
    if not result.reports_generated:
        raise HTTPException(status_code=404, detail="No reports available for this hunt")
    
    saved_files = {}
    
    for report in result.reports_generated:
        try:
            files = auto_hunter.report_builder.save_report(
                report=report,
                formats=formats
            )
            saved_files[report.title] = {
                fmt: str(path) for fmt, path in files.items()
            }
        except Exception as e:
            logger.error(f"Failed to save report {report.title}: {e}")
    
    return {
        "hunt_id": hunt_id,
        "reports_saved": len(saved_files),
        "files": saved_files
    }


@router.get("/health")
async def health_check():
    """
    Health check for Bug Bounty Autopilot
    
    Checks:
    - Burp Suite connectivity
    - Component initialization
    - System readiness
    """
    burp_running = auto_hunter.burp.is_burp_running()
    
    return {
        "status": "healthy" if burp_running else "degraded",
        "burp_suite_connected": burp_running,
        "components": {
            "burp_controller": True,
            "scanner_manager": True,
            "poc_generator": True,
            "report_builder": True,
            "auto_hunter": True,
            "auto_submitter": True
        },
        "active_hunts": len(auto_hunter.get_active_hunts())
    }


# === NEW: Platform Submission Endpoints ===

class SubmissionRequest(BaseModel):
    """Universal submission request for any platform"""
    platform: str
    program: str
    report_data: Dict[str, Any]


class BatchSubmissionRequest(BaseModel):
    """Batch submission request"""
    submissions: List[Dict[str, Any]]


@router.get("/platforms")
async def get_available_platforms():
    """
    Get list of configured bug bounty platforms.
    
    Returns platforms that have valid API credentials configured.
    """
    try:
        platforms = auto_submitter.get_available_platforms()
        
        return {
            "platforms": platforms,
            "count": len(platforms),
            "supported": ["hackerone", "bugcrowd", "intigriti", "yeswehack"]
        }
    except Exception as e:
        logger.error(f"Failed to get platforms: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/platforms/{platform}/programs")
async def get_platform_programs(platform: str):
    """
    Get list of programs for a specific platform.
    
    Args:
        platform: Platform name (hackerone, bugcrowd, intigriti, yeswehack)
    """
    try:
        if not auto_submitter.is_platform_configured(platform):
            raise HTTPException(
                status_code=400,
                detail=f"Platform {platform} is not configured. Add API credentials to .env"
            )
        
        client = auto_submitter.clients[platform.lower()]
        programs = client.get_programs()
        
        return {
            "platform": platform,
            "programs": programs,
            "count": len(programs)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get programs for {platform}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/submit")
async def submit_report(request: SubmissionRequest):
    """
    Submit bug bounty report to specified platform.
    
    This endpoint handles the complete submission workflow:
    1. Validates platform configuration
    2. Formats report data according to platform requirements
    3. Submits report with attachments
    4. Returns submission confirmation with ID
    
    Example request for HackerOne:
    ```json
    {
        "platform": "hackerone",
        "program": "security",
        "report_data": {
            "title": "SQL Injection in Login",
            "vulnerability_type": "sql_injection",
            "severity": "critical",
            "description": "...",
            "steps_to_reproduce": "...",
            "impact": "...",
            "proof_of_concept": "...",
            "attachments": ["/path/to/screenshot.png"]
        }
    }
    ```
    """
    try:
        if not auto_submitter.is_platform_configured(request.platform):
            available = auto_submitter.get_available_platforms()
            raise HTTPException(
                status_code=400,
                detail=f"Platform {request.platform} is not configured. Available: {available}"
            )
        
        result = auto_submitter.submit(
            platform=request.platform,
            program=request.program,
            report_data=request.report_data
        )
        
        logger.info(f"Successfully submitted report to {request.platform}: {result}")
        
        return {
            "success": True,
            "platform": request.platform,
            "submission": result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/submit-batch")
async def submit_batch_reports(request: BatchSubmissionRequest):
    """
    Submit multiple reports to different platforms in batch.
    
    Useful for submitting the same vulnerability to multiple programs
    or submitting multiple vulnerabilities at once.
    
    Example:
    ```json
    {
        "submissions": [
            {
                "platform": "hackerone",
                "program": "security",
                "report_data": {...}
            },
            {
                "platform": "bugcrowd",
                "program": "uber",
                "report_data": {...}
            }
        ]
    }
    ```
    """
    try:
        results = auto_submitter.submit_batch(request.submissions)
        
        success_count = sum(1 for r in results if r.get('success'))
        failed_count = len(results) - success_count
        
        return {
            "total": len(results),
            "successful": success_count,
            "failed": failed_count,
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Batch submission failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/submissions/{submission_id}/status")
async def get_submission_status(
    submission_id: str,
    platform: str
):
    """
    Get status of a submitted report.
    
    Args:
        submission_id: Report/Submission ID from platform
        platform: Platform name
        
    Returns status including:
    - Current state (new, triaged, resolved, etc.)
    - Bounty amount if awarded
    - Timeline information
    """
    try:
        if not auto_submitter.is_platform_configured(platform):
            raise HTTPException(
                status_code=400,
                detail=f"Platform {platform} is not configured"
            )
        
        status = auto_submitter.get_submission_status(platform, submission_id)
        
        return {
            "platform": platform,
            "submission_id": submission_id,
            "status": status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get submission status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/estimate-payout")
async def estimate_payout(
    platform: str,
    program: str,
    severity: str,
    vulnerability_type: str
):
    """
    Estimate potential payout for a vulnerability.
    
    Provides min, max, and average payout estimates based on:
    - Platform bounty tables
    - Program history
    - Severity rating
    - Vulnerability type
    
    Note: These are estimates only. Actual payout depends on many factors.
    """
    try:
        if not auto_submitter.is_platform_configured(platform):
            raise HTTPException(
                status_code=400,
                detail=f"Platform {platform} is not configured"
            )
        
        estimate = auto_submitter.estimate_payout(
            platform=platform,
            program=program,
            severity=severity,
            vulnerability_type=vulnerability_type
        )
        
        return {
            "platform": platform,
            "program": program,
            "severity": severity,
            "vulnerability_type": vulnerability_type,
            "estimate": estimate,
            "note": "Estimates only. Actual payout may vary significantly."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to estimate payout: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auto-format-report")
async def auto_format_report(
    platform: str,
    vulnerability: Dict[str, Any]
):
    """
    Auto-format vulnerability data for specific platform requirements.
    
    Takes raw vulnerability data from scanner and formats it
    according to the target platform's API requirements.
    
    Useful when you have scan results and want to quickly
    format them for submission without manual data mapping.
    """
    try:
        formatted = auto_submitter.format_report_for_platform(
            platform=platform,
            vulnerability=vulnerability
        )
        
        return {
            "platform": platform,
            "formatted_report": formatted
        }
        
    except Exception as e:
        logger.error(f"Failed to format report: {e}")
        raise HTTPException(status_code=500, detail=str(e))
