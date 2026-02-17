from typing import Dict, List, Optional, Any
from datetime import datetime
from src.config import settings
from src.utils.logger import get_logger
from src.bugbounty.platforms import (
    HackerOneClient,
    BugcrowdClient,
    IntigritiClient,
    YesWeHackClient
)

logger = get_logger(__name__)


class AutoSubmitter:
    """
    Unified interface for submitting bug bounty reports to multiple platforms.
    
    Supports: HackerOne, Bugcrowd, Intigriti, YesWeHack
    """
    
    def __init__(self):
        """Initialize platform clients based on configuration."""
        self.clients = {}
        
        # Initialize HackerOne client
        if hasattr(settings, 'hackerone_username') and hasattr(settings, 'hackerone_api_token'):
            if settings.hackerone_username and settings.hackerone_api_token:
                self.clients['hackerone'] = HackerOneClient(
                    username=settings.hackerone_username,
                    api_token=settings.hackerone_api_token
                )
                logger.info("HackerOne client initialized")
        
        # Initialize Bugcrowd client
        if hasattr(settings, 'bugcrowd_email') and hasattr(settings, 'bugcrowd_api_key'):
            if settings.bugcrowd_email and settings.bugcrowd_api_key:
                self.clients['bugcrowd'] = BugcrowdClient(
                    email=settings.bugcrowd_email,
                    api_key=settings.bugcrowd_api_key
                )
                logger.info("Bugcrowd client initialized")
        
        # Initialize Intigriti client
        if hasattr(settings, 'intigriti_api_token') and settings.intigriti_api_token:
            self.clients['intigriti'] = IntigritiClient(
                api_token=settings.intigriti_api_token
            )
            logger.info("Intigriti client initialized")
        
        # Initialize YesWeHack client
        if hasattr(settings, 'yeswehack_api_token') and settings.yeswehack_api_token:
            self.clients['yeswehack'] = YesWeHackClient(
                api_token=settings.yeswehack_api_token
            )
            logger.info("YesWeHack client initialized")
    
    def get_available_platforms(self) -> List[str]:
        """Get list of configured platforms."""
        return list(self.clients.keys())
    
    def is_platform_configured(self, platform: str) -> bool:
        """Check if a platform is configured."""
        return platform.lower() in self.clients
    
    def submit_to_hackerone(
        self,
        program_handle: str,
        title: str,
        vulnerability_type: str,
        severity: str,
        description: str,
        steps_to_reproduce: str,
        impact: str,
        proof_of_concept: Optional[str] = None,
        attachments: Optional[List[str]] = None,
        weakness_id: Optional[int] = None
    ) -> Dict:
        """Submit report to HackerOne."""
        if 'hackerone' not in self.clients:
            raise Exception("HackerOne client not configured")
        
        client = self.clients['hackerone']
        
        return client.submit_complete_report(
            program_handle=program_handle,
            title=title,
            vulnerability_type=vulnerability_type,
            severity=severity,
            description=description,
            steps_to_reproduce=steps_to_reproduce,
            impact=impact,
            proof_of_concept=proof_of_concept,
            attachments=attachments,
            weakness_id=weakness_id
        )
    
    def submit_to_bugcrowd(
        self,
        program_code: str,
        title: str,
        description: str,
        severity: str,
        endpoint: str,
        discovery_details: str,
        impact_details: str,
        proof_of_concept: Optional[str] = None,
        attachments: Optional[List[str]] = None,
        recommendation: Optional[str] = None,
        vulnerability_category: Optional[str] = None
    ) -> Dict:
        """Submit report to Bugcrowd."""
        if 'bugcrowd' not in self.clients:
            raise Exception("Bugcrowd client not configured")
        
        client = self.clients['bugcrowd']
        
        return client.submit_complete_report(
            program_code=program_code,
            title=title,
            description=description,
            severity=severity,
            endpoint=endpoint,
            discovery_details=discovery_details,
            impact_details=impact_details,
            proof_of_concept=proof_of_concept,
            attachments=attachments,
            recommendation=recommendation,
            vulnerability_category=vulnerability_category
        )
    
    def submit_to_intigriti(
        self,
        program_id: str,
        title: str,
        description: str,
        severity: int,
        endpoint: str,
        vulnerability_type_id: int,
        steps_to_reproduce: str,
        impact: str,
        proof_of_concept: Optional[str] = None,
        attachments: Optional[List[str]] = None
    ) -> Dict:
        """Submit report to Intigriti."""
        if 'intigriti' not in self.clients:
            raise Exception("Intigriti client not configured")
        
        client = self.clients['intigriti']
        
        return client.submit_complete_report(
            program_id=program_id,
            title=title,
            description=description,
            severity=severity,
            endpoint=endpoint,
            vulnerability_type_id=vulnerability_type_id,
            steps_to_reproduce=steps_to_reproduce,
            impact=impact,
            proof_of_concept=proof_of_concept,
            attachments=attachments
        )
    
    def submit_to_yeswehack(
        self,
        program_slug: str,
        title: str,
        description: str,
        severity: str,
        cvss_vector: Optional[str],
        vulnerability_type: str,
        affected_assets: List[str],
        steps_to_reproduce: str,
        impact_description: str,
        proof_of_concept: Optional[str] = None,
        attachments: Optional[List[str]] = None,
        remediation_advice: Optional[str] = None
    ) -> Dict:
        """Submit report to YesWeHack."""
        if 'yeswehack' not in self.clients:
            raise Exception("YesWeHack client not configured")
        
        client = self.clients['yeswehack']
        
        return client.submit_complete_report(
            program_slug=program_slug,
            title=title,
            description=description,
            severity=severity,
            cvss_vector=cvss_vector,
            vulnerability_type=vulnerability_type,
            affected_assets=affected_assets,
            steps_to_reproduce=steps_to_reproduce,
            impact_description=impact_description,
            proof_of_concept=proof_of_concept,
            attachments=attachments,
            remediation_advice=remediation_advice
        )
    
    def submit(
        self,
        platform: str,
        program: str,
        report_data: Dict[str, Any]
    ) -> Dict:
        """
        Universal submit method - automatically routes to correct platform.
        
        Args:
            platform: Platform name (hackerone, bugcrowd, intigriti, yeswehack)
            program: Program handle/code/id/slug
            report_data: Report data dictionary
            
        Returns:
            Submission result with ID and status
        """
        platform = platform.lower()
        
        if not self.is_platform_configured(platform):
            raise Exception(f"Platform {platform} is not configured")
        
        logger.info(f"Submitting report to {platform} - {program}")
        
        try:
            if platform == 'hackerone':
                return self.submit_to_hackerone(
                    program_handle=program,
                    **report_data
                )
            elif platform == 'bugcrowd':
                return self.submit_to_bugcrowd(
                    program_code=program,
                    **report_data
                )
            elif platform == 'intigriti':
                return self.submit_to_intigriti(
                    program_id=program,
                    **report_data
                )
            elif platform == 'yeswehack':
                return self.submit_to_yeswehack(
                    program_slug=program,
                    **report_data
                )
            else:
                raise Exception(f"Unknown platform: {platform}")
                
        except Exception as e:
            logger.error(f"Failed to submit to {platform}: {e}")
            raise
    
    def submit_batch(
        self,
        submissions: List[Dict[str, Any]]
    ) -> List[Dict]:
        """
        Submit multiple reports to different platforms.
        
        Args:
            submissions: List of submission dictionaries, each containing:
                - platform: Platform name
                - program: Program identifier
                - report_data: Report data
                
        Returns:
            List of submission results
        """
        results = []
        
        for submission in submissions:
            try:
                result = self.submit(
                    platform=submission['platform'],
                    program=submission['program'],
                    report_data=submission['report_data']
                )
                results.append({
                    'success': True,
                    'platform': submission['platform'],
                    'result': result
                })
            except Exception as e:
                results.append({
                    'success': False,
                    'platform': submission['platform'],
                    'error': str(e)
                })
                logger.error(f"Batch submission failed for {submission['platform']}: {e}")
        
        return results
    
    def get_submission_status(
        self,
        platform: str,
        submission_id: str
    ) -> Dict:
        """
        Get status of a submitted report.
        
        Args:
            platform: Platform name
            submission_id: Submission/Report ID
            
        Returns:
            Status information
        """
        platform = platform.lower()
        
        if not self.is_platform_configured(platform):
            raise Exception(f"Platform {platform} is not configured")
        
        client = self.clients[platform]
        
        if platform == 'hackerone':
            return client.get_report_status(submission_id)
        elif platform == 'bugcrowd':
            return client.get_submission_status(submission_id)
        elif platform == 'intigriti':
            return client.get_submission_status(submission_id)
        elif platform == 'yeswehack':
            return client.get_report_status(submission_id)
    
    def estimate_payout(
        self,
        platform: str,
        program: str,
        severity: str,
        vulnerability_type: str
    ) -> Dict[str, float]:
        """
        Estimate potential payout for a vulnerability.
        
        Args:
            platform: Platform name
            program: Program identifier
            severity: Severity rating
            vulnerability_type: Type of vulnerability
            
        Returns:
            Dict with min, max, avg payout estimates
        """
        platform = platform.lower()
        
        if not self.is_platform_configured(platform):
            raise Exception(f"Platform {platform} is not configured")
        
        client = self.clients[platform]
        
        return client.estimate_payout(program, severity, vulnerability_type)
    
    def format_report_for_platform(
        self,
        platform: str,
        vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Auto-format vulnerability data for specific platform requirements.
        
        Args:
            platform: Target platform
            vulnerability: Vulnerability data from scanner
            
        Returns:
            Formatted report data ready for submission
        """
        platform = platform.lower()
        
        # Common fields from scanner
        title = vulnerability.get('title', 'Untitled Vulnerability')
        description = vulnerability.get('description', '')
        severity = vulnerability.get('severity', 'medium')
        endpoint = vulnerability.get('url', '')
        poc = vulnerability.get('poc', '')
        steps = vulnerability.get('steps_to_reproduce', '')
        impact = vulnerability.get('impact', '')
        
        if platform == 'hackerone':
            return {
                'title': title,
                'vulnerability_type': vulnerability.get('type', 'other'),
                'severity': severity,
                'description': description,
                'steps_to_reproduce': steps,
                'impact': impact,
                'proof_of_concept': poc,
                'attachments': vulnerability.get('attachments', [])
            }
        
        elif platform == 'bugcrowd':
            # Map severity to P1-P5
            severity_map = {
                'critical': 'P1',
                'high': 'P2',
                'medium': 'P3',
                'low': 'P4',
                'info': 'P5'
            }
            return {
                'title': title,
                'description': description,
                'severity': severity_map.get(severity, 'P3'),
                'endpoint': endpoint,
                'discovery_details': steps,
                'impact_details': impact,
                'proof_of_concept': poc,
                'attachments': vulnerability.get('attachments', []),
                'vulnerability_category': vulnerability.get('type')
            }
        
        elif platform == 'intigriti':
            # Map severity to 1-4
            severity_map = {
                'critical': 4,
                'high': 3,
                'medium': 2,
                'low': 1
            }
            return {
                'title': title,
                'description': description,
                'severity': severity_map.get(severity, 2),
                'endpoint': endpoint,
                'vulnerability_type_id': 1,  # Default, should be mapped properly
                'steps_to_reproduce': steps,
                'impact': impact,
                'proof_of_concept': poc,
                'attachments': vulnerability.get('attachments', [])
            }
        
        elif platform == 'yeswehack':
            return {
                'title': title,
                'description': description,
                'severity': severity,
                'cvss_vector': vulnerability.get('cvss_vector'),
                'vulnerability_type': vulnerability.get('type', 'other'),
                'affected_assets': [endpoint],
                'steps_to_reproduce': steps,
                'impact_description': impact,
                'proof_of_concept': poc,
                'attachments': vulnerability.get('attachments', [])
            }
        
        else:
            raise Exception(f"Unknown platform: {platform}")
