import requests
import os
from typing import Dict, List, Optional
from pathlib import Path
from src.utils.logger import get_logger

logger = get_logger(__name__)


class BugcrowdClient:
    """
    Bugcrowd API client for automated bug bounty report submission.
    
    API Documentation: https://docs.bugcrowd.com/api/
    """
    
    BASE_URL = "https://api.bugcrowd.com"
    
    def __init__(self, email: str, api_key: str):
        """
        Initialize Bugcrowd client with API credentials.
        
        Args:
            email: Bugcrowd account email
            api_key: Bugcrowd API key (from Settings > API)
        """
        self.email = email
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {api_key}',
            'Content-Type': 'application/vnd.bugcrowd.v4+json',
            'Accept': 'application/vnd.bugcrowd.v4+json'
        })
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        files: Optional[Dict] = None
    ) -> Dict:
        """Make authenticated API request."""
        url = f"{self.BASE_URL}/{endpoint}"
        
        try:
            if files:
                # For file uploads, don't set Content-Type
                headers = dict(self.session.headers)
                headers.pop('Content-Type', None)
                response = requests.request(
                    method=method,
                    url=url,
                    data=data,
                    files=files,
                    headers=headers,
                    timeout=60
                )
            else:
                response = self.session.request(
                    method=method,
                    url=url,
                    json=data,
                    params=params,
                    timeout=30
                )
            
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.exceptions.RequestException as e:
            logger.error(f"Bugcrowd API request failed: {e}")
            raise Exception(f"Bugcrowd API error: {str(e)}")
    
    def get_programs(self) -> List[Dict]:
        """Get list of programs."""
        try:
            response = self._make_request('GET', 'programs')
            return response.get('programs', [])
        except Exception as e:
            logger.error(f"Failed to get programs: {e}")
            return []
    
    def get_program(self, program_code: str) -> Optional[Dict]:
        """Get program details by code."""
        try:
            response = self._make_request('GET', f'programs/{program_code}')
            return response
        except Exception as e:
            logger.error(f"Failed to get program {program_code}: {e}")
            return None
    
    def create_submission(
        self,
        program_code: str,
        title: str,
        description: str,
        severity: str,
        endpoint: str,
        discovery_details: str,
        impact_details: str,
        recommendation: Optional[str] = None,
        vulnerability_category: Optional[str] = None
    ) -> Dict:
        """
        Create a new submission (bug report).
        
        Args:
            program_code: Program code (e.g., 'uber')
            title: Submission title
            description: Detailed description
            severity: Severity (P1-P5, where P1 is critical)
            endpoint: Affected endpoint/URL
            discovery_details: How you discovered the vulnerability
            impact_details: Impact description
            recommendation: Remediation recommendation
            vulnerability_category: Category (e.g., 'xss', 'sqli')
            
        Returns:
            Submission data with ID
        """
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "endpoint": endpoint,
            "discovery_details": discovery_details,
            "impact": impact_details,
            "program": program_code
        }
        
        if recommendation:
            payload["recommendation"] = recommendation
        
        if vulnerability_category:
            payload["vulnerability_type"] = vulnerability_category
        
        try:
            response = self._make_request(
                'POST',
                f'programs/{program_code}/submissions',
                data=payload
            )
            submission_id = response.get('id') or response.get('uuid')
            logger.info(f"Created Bugcrowd submission #{submission_id} for {program_code}")
            return response
        except Exception as e:
            logger.error(f"Failed to create submission: {e}")
            raise
    
    def upload_attachment(self, submission_id: str, file_path: str) -> Dict:
        """
        Upload an attachment to a submission.
        
        Args:
            submission_id: Submission ID
            file_path: Path to file
            
        Returns:
            Attachment data
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        filename = Path(file_path).name
        
        with open(file_path, 'rb') as f:
            files = {'file': (filename, f, 'application/octet-stream')}
            
            try:
                response = self._make_request(
                    'POST',
                    f'submissions/{submission_id}/attachments',
                    files=files
                )
                logger.info(f"Uploaded attachment: {filename}")
                return response
            except Exception as e:
                logger.error(f"Failed to upload attachment: {e}")
                raise
    
    def add_comment(self, submission_id: str, comment: str) -> Dict:
        """Add a comment to a submission."""
        payload = {
            "comment": comment
        }
        
        try:
            response = self._make_request(
                'POST',
                f'submissions/{submission_id}/comments',
                data=payload
            )
            logger.info(f"Added comment to submission #{submission_id}")
            return response
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            raise
    
    def get_submission_status(self, submission_id: str) -> Dict:
        """Get submission status and details."""
        try:
            response = self._make_request('GET', f'submissions/{submission_id}')
            
            status_info = {
                'id': response.get('id') or response.get('uuid'),
                'title': response.get('title'),
                'state': response.get('state'),
                'severity': response.get('severity'),
                'created_at': response.get('created_at'),
                'updated_at': response.get('updated_at'),
                'bounty_awarded': response.get('bounty_amount') is not None
            }
            
            return status_info
        except Exception as e:
            logger.error(f"Failed to get submission status: {e}")
            raise
    
    def get_bounty_amount(self, submission_id: str) -> Optional[float]:
        """Get bounty amount if awarded."""
        try:
            response = self._make_request('GET', f'submissions/{submission_id}')
            amount = response.get('bounty_amount')
            return float(amount) if amount else None
        except Exception as e:
            logger.error(f"Failed to get bounty amount: {e}")
            return None
    
    def submit_complete_report(
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
        """
        Complete workflow: Create submission and add PoC/attachments.
        
        Args:
            program_code: Program code
            title: Title
            description: Description
            severity: Severity (P1-P5)
            endpoint: Affected endpoint
            discovery_details: Discovery details
            impact_details: Impact
            proof_of_concept: PoC code
            attachments: File paths to attach
            recommendation: Remediation recommendation
            vulnerability_category: Vulnerability type
            
        Returns:
            Complete submission data
        """
        logger.info(f"Submitting report to Bugcrowd {program_code}: {title}")
        
        # Step 1: Create submission
        submission = self.create_submission(
            program_code=program_code,
            title=title,
            description=description,
            severity=severity,
            endpoint=endpoint,
            discovery_details=discovery_details,
            impact_details=impact_details,
            recommendation=recommendation,
            vulnerability_category=vulnerability_category
        )
        
        submission_id = submission.get('id') or submission.get('uuid')
        
        # Step 2: Upload attachments
        if attachments:
            for file_path in attachments:
                try:
                    self.upload_attachment(submission_id, file_path)
                except Exception as e:
                    logger.warning(f"Failed to upload {file_path}: {e}")
        
        # Step 3: Add PoC as comment
        if proof_of_concept:
            poc_comment = f"## Proof of Concept\n\n```\n{proof_of_concept}\n```"
            try:
                self.add_comment(submission_id, poc_comment)
            except Exception as e:
                logger.warning(f"Failed to add PoC comment: {e}")
        
        logger.info(f"Successfully submitted Bugcrowd report #{submission_id}")
        
        return {
            'submission_id': submission_id,
            'program': program_code,
            'title': title,
            'severity': severity,
            'status': 'submitted',
            'created_at': submission.get('created_at'),
            'url': f"https://bugcrowd.com/submissions/{submission_id}"
        }
    
    def map_severity_from_cvss(self, cvss_score: float) -> str:
        """
        Map CVSS score to Bugcrowd severity (P1-P5).
        
        Args:
            cvss_score: CVSS score (0.0-10.0)
            
        Returns:
            Bugcrowd severity (P1-P5)
        """
        if cvss_score >= 9.0:
            return "P1"  # Critical
        elif cvss_score >= 7.0:
            return "P2"  # High
        elif cvss_score >= 4.0:
            return "P3"  # Medium
        elif cvss_score >= 0.1:
            return "P4"  # Low
        else:
            return "P5"  # Informational
    
    def estimate_payout(
        self,
        program_code: str,
        severity: str,
        vulnerability_type: str
    ) -> Dict[str, float]:
        """
        Estimate payout based on severity.
        
        Returns:
            Dict with 'min', 'max', 'avg' payout estimates in USD
        """
        ranges = {
            'P1': {'min': 3000, 'max': 30000, 'avg': 10000},
            'P2': {'min': 1000, 'max': 10000, 'avg': 4000},
            'P3': {'min': 300, 'max': 3000, 'avg': 1200},
            'P4': {'min': 100, 'max': 500, 'avg': 250},
            'P5': {'min': 0, 'max': 100, 'avg': 25}
        }
        
        return ranges.get(severity.upper(), ranges['P5'])
