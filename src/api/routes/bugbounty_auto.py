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
from src.bugbounty.program_analyzer import ProgramAnalyzer, KNOWN_PROGRAMS
from src.security.bugbounty.scope_validator import ScopeValidator, Program
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/bugbounty/auto", tags=["Bug Bounty Autopilot"])

auto_hunter = AutoHunter()
auto_submitter = AutoSubmitter()
program_analyzer = ProgramAnalyzer()

programs: Dict[str, ScopeValidator] = {}


class AutoHuntRequest(BaseModel):
    target_url: str
    program: str = "general"
    program_scope: Optional[List[str]] = None
    auto_poc: bool = True
    auto_report: bool = True
    report_formats: List[str] = ["markdown", "html", "json"]
    enable_voice: bool = False  # Enable Hindi-English voice notifications


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


class ProgramAnalyzeRequest(BaseModel):
    program_url: str
    

class ScopeCheckRequest(BaseModel):
    program_url: str
    target_url: str


@router.post("/analyze-program")
async def analyze_program(request: ProgramAnalyzeRequest):
    """
    Autonomously analyze a bug bounty program
    
    Aether will:
    1. Fetch the program page
    2. Extract scope (in-scope/out-of-scope domains)
    3. Extract rules (allowed/forbidden actions)
    4. Extract payout information
    5. Return structured data
    
    NO HUMAN INPUT NEEDED - fully autonomous!
    
    Example:
        POST /api/v1/bugbounty/auto/analyze-program
        {
            "program_url": "https://security.apple.com/bounty/"
        }
    
    Returns:
        Complete program information including scope, rules, and payouts
    """
    try:
        logger.info(f"Analyzing program: {request.program_url}")
        
        program = await program_analyzer.analyze_program(request.program_url)
        
        program_dict = program_analyzer.program_to_dict(program)
        
        logger.info(f"Program analyzed: {program.name} (confidence: {program.confidence_score:.2%})")
        
        return {
            "success": True,
            "program": program_dict,
            "message": f"Program '{program.name}' analyzed successfully"
        }
        
    except Exception as e:
        logger.error(f"Program analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/check-scope")
async def check_scope(request: ScopeCheckRequest):
    """
    Check if a target is in scope for a program
    
    Quick autonomous check without full analysis.
    
    Example:
        POST /api/v1/bugbounty/auto/check-scope
        {
            "program_url": "https://security.apple.com/bounty/",
            "target_url": "www.apple.com"
        }
    
    Returns:
        Whether target is in scope
    """
    try:
        is_in_scope = await program_analyzer.quick_scope_check(
            request.program_url,
            request.target_url
        )
        
        return {
            "success": True,
            "target": request.target_url,
            "in_scope": is_in_scope,
            "message": "In scope" if is_in_scope else "Out of scope"
        }
        
    except Exception as e:
        logger.error(f"Scope check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/known-programs")
async def get_known_programs():
    """
    Get list of known bug bounty programs
    
    These programs have pre-configured URLs for quick analysis.
    
    Returns:
        Dictionary of program shortcuts
    """
    return {
        "success": True,
        "programs": KNOWN_PROGRAMS,
        "count": len(KNOWN_PROGRAMS),
        "message": "Use these shortcuts for quick program analysis"
    }


@router.post("/smart-hunt")
async def smart_hunt(
    request: AutoHuntRequest,
    background_tasks: BackgroundTasks
):
    """
    FULLY AUTONOMOUS BUG HUNT!
    
    Aether will:
    1. Analyze the program page (extract scope, rules)
    2. Validate target is in scope
    3. Configure Burp Suite automatically
    4. Run scan within program rules
    5. Analyze findings
    6. Generate PoCs and reports
    7. Return everything ready for submission
    
    THIS IS THE GOD MODE - NO HUMAN INPUT NEEDED!
    
    Example:
        POST /api/v1/bugbounty/auto/smart-hunt
        {
            "target_url": "https://www.apple.com",
            "program": "apple"
        }
    
    Returns:
        Hunt ID for tracking
    """
    try:
        logger.info(f"Starting SMART HUNT on {request.target_url}")
        
        # Step 1: Get program URL
        program_url = None
        if request.program in KNOWN_PROGRAMS:
            program_url = KNOWN_PROGRAMS[request.program]
        elif request.program.startswith("http"):
            program_url = request.program
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown program '{request.program}'. Use /known-programs to see available shortcuts"
            )
        
        # Step 2: Analyze program autonomously (with voice if enabled)
        logger.info(f"Analyzing program: {program_url}")
        
        if request.enable_voice:
            voice_analyzer = ProgramAnalyzer(enable_voice=True)
            program_data = await voice_analyzer.analyze_program(program_url)
        else:
            program_data = await program_analyzer.analyze_program(program_url)
        
        # Step 3: Validate scope
        from urllib.parse import urlparse
        target_domain = urlparse(request.target_url).netloc
        
        is_in_scope = await program_analyzer.quick_scope_check(
            program_url,
            target_domain
        )
        
        if not is_in_scope:
            raise HTTPException(
                status_code=403,
                detail=f"Target {target_domain} is OUT OF SCOPE for {program_data.name}"
            )
        
        logger.info(f"Target {target_domain} confirmed IN SCOPE")
        
        # Step 4: Create scope validator from analyzed data
        temp_program = Program(
            name=program_data.name,
            platform=program_data.platform,
            in_scope=program_data.scope.in_scope,
            out_of_scope=program_data.scope.out_of_scope
        )
        scope_validator = ScopeValidator(temp_program)
        
        # Step 5: Start autonomous hunt (with voice if enabled)
        async def run_smart_hunt():
            try:
                if request.enable_voice:
                    voice_hunter = AutoHunter(enable_voice=True)
                    result = await voice_hunter.start_auto_hunt(
                        target_url=request.target_url,
                        program=program_data.name,
                        scope_validator=scope_validator,
                        auto_poc=request.auto_poc,
                        auto_report=request.auto_report,
                        report_formats=request.report_formats
                    )
                else:
                    result = await auto_hunter.start_auto_hunt(
                        target_url=request.target_url,
                        program=program_data.name,
                        scope_validator=scope_validator,
                        auto_poc=request.auto_poc,
                        auto_report=request.auto_report,
                        report_formats=request.report_formats
                    )
                
                if result.status == ScanStatus.COMPLETED:
                    logger.info(f"SMART HUNT completed: {result.total_issues_found} findings")
                else:
                    logger.error(f"SMART HUNT failed: {result.error_message}")
                    
            except Exception as e:
                logger.error(f"SMART HUNT execution failed: {e}", exc_info=True)
        
        background_tasks.add_task(run_smart_hunt)
        
        hunt_id = f"smart_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return {
            "hunt_id": hunt_id,
            "status": "started",
            "message": f"SMART HUNT started on {program_data.name}",
            "program_info": {
                "name": program_data.name,
                "platform": program_data.platform,
                "max_payout": program_data.payouts.max_payout,
                "confidence": program_data.confidence_score
            },
            "target": request.target_url,
            "in_scope": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SMART HUNT failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


manual_testing_agent = None


class ManualTestingRequest(BaseModel):
    """Request to start manual testing session"""
    target_domain: str
    session_name: Optional[str] = None
    auto_test: bool = True
    user_approval: bool = True
    enable_voice: bool = False


@router.post("/manual-testing/start")
async def start_manual_testing(request: ManualTestingRequest):
    """
    Start AI-powered manual testing session
    
    This is THE ULTIMATE MANUAL TESTING MODE - Replicates expert human testing!
    
    Features:
    - Watches Burp Suite intercept in real-time
    - AI analyzes EVERY request for context
    - Generates context-aware payloads (not generic!)
    - Detects subtle response anomalies
    - Makes human-like decisions (forward/drop/modify)
    - Learns from responses (builds application knowledge)
    - Chains exploits creatively!
    
    Example:
        POST /api/v1/bugbounty/auto/manual-testing/start
        {
            "target_domain": "apple.com",
            "auto_test": true,
            "enable_voice": true
        }
        
    Returns:
        Session ID for tracking
    """
    global manual_testing_agent
    
    try:
        from src.bugbounty.manual_testing_agent import ManualTestingAgent
        from src.security.bugbounty.burp_integration import BurpSuiteClient
        
        if not manual_testing_agent:
            burp_client = BurpSuiteClient()
            manual_testing_agent = ManualTestingAgent(
                burp_client=burp_client,
                enable_voice=request.enable_voice
            )
        
        session_id = await manual_testing_agent.start_manual_testing(
            target_domain=request.target_domain,
            session_name=request.session_name,
            auto_test=request.auto_test,
            user_approval=request.user_approval
        )
        
        logger.info(f"Manual testing session started: {session_id}")
        
        return {
            "session_id": session_id,
            "status": "active",
            "message": f"AI manual testing active for {request.target_domain}",
            "features": [
                "Burp intercept monitoring",
                "AI request analysis",
                "Context-aware payloads",
                "Response anomaly detection",
                "Smart decision making",
                "Learning loop",
                "Exploit chaining"
            ],
            "target": request.target_domain,
            "auto_test": request.auto_test,
            "voice_enabled": request.enable_voice
        }
        
    except Exception as e:
        logger.error(f"Failed to start manual testing: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/manual-testing/stop/{session_id}")
async def stop_manual_testing(session_id: str):
    """
    Stop manual testing session
    
    Returns final statistics and discovered vulnerabilities
    """
    global manual_testing_agent
    
    if not manual_testing_agent:
        raise HTTPException(status_code=404, detail="No active manual testing session")
    
    try:
        session = await manual_testing_agent.stop_manual_testing(session_id)
        
        if not session:
            raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
        
        stats = manual_testing_agent.get_session_stats(session_id)
        
        return {
            "session_id": session_id,
            "status": "stopped",
            "statistics": stats
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to stop manual testing: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/manual-testing/stats/{session_id}")
async def get_manual_testing_stats(session_id: str):
    """
    Get real-time statistics for manual testing session
    
    Shows:
    - Requests intercepted/modified/forwarded/dropped
    - Vulnerabilities found
    - Exploit chains discovered
    - Application insights learned
    """
    global manual_testing_agent
    
    if not manual_testing_agent:
        raise HTTPException(status_code=404, detail="No active manual testing session")
    
    try:
        stats = manual_testing_agent.get_session_stats(session_id)
        
        if "error" in stats:
            raise HTTPException(status_code=404, detail=stats["error"])
        
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


logger.info("✅ Manual Testing API endpoints registered - /manual-testing/start, /stop, /stats")
