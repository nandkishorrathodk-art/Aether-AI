import requests
import os
from typing import Dict, List, Optional
from pathlib import Path
from src.utils.logger import get_logger

logger = get_logger(__name__)


class IntigritiClient:
    """
    Intigriti API client for automated bug bounty report submission.
    
    API Documentation: https://app.intigriti.com/researcher/documentation
    """
    
    BASE_URL = "https://api.intigriti.com"
    
    def __init__(self, api_token: str):
        """
        Initialize Intigriti client with API credentials.
        
        Args:
            api_token: Intigriti API token (from Profile > API Tokens)
        """
        self.api_token = api_token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
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
                headers = {'Authorization': f'Bearer {self.api_token}'}
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
            logger.error(f"Intigriti API request failed: {e}")
            raise Exception(f"Intigriti API error: {str(e)}")
    
    def get_programs(self) -> List[Dict]:
        """Get list of available programs."""
        try:
            response = self._make_request('GET', 'core/program')
            return response.get('records', [])
        except Exception as e:
            logger.error(f"Failed to get programs: {e}")
            return []
    
    def get_program(self, program_id: str) -> Optional[Dict]:
        """Get program details by ID."""
        try:
            response = self._make_request('GET', f'core/program/{program_id}')
            return response
        except Exception as e:
            logger.error(f"Failed to get program {program_id}: {e}")
            return None
    
    def create_submission(
        self,
        program_id: str,
        title: str,
        description: str,
        severity: int,
        endpoint: str,
        vulnerability_type_id: int,
        steps_to_reproduce: str,
        impact: str,
        proof_of_concept: Optional[str] = None
    ) -> Dict:
        """
        Create a new submission.
        
        Args:
            program_id: Program ID
            title: Submission title
            description: Detailed description
            severity: Severity (1=Low, 2=Medium, 3=High, 4=Critical)
            endpoint: Affected endpoint/URL
            vulnerability_type_id: Vulnerability type ID from Intigriti
            steps_to_reproduce: Reproduction steps
            impact: Impact description
            proof_of_concept: PoC code/details
            
        Returns:
            Submission data with ID
        """
        payload = {
            "programId": program_id,
            "title": title,
            "description": description,
            "severity": severity,
            "endpoint": endpoint,
            "vulnerabilityTypeId": vulnerability_type_id,
            "reproducibilityDescription": steps_to_reproduce,
            "impactDescription": impact
        }
        
        if proof_of_concept:
            payload["proofOfConceptDescription"] = proof_of_concept
        
        try:
            response = self._make_request(
                'POST',
                'core/submission',
                data=payload
            )
            submission_id = response.get('submissionId')
            logger.info(f"Created Intigriti submission #{submission_id} for program {program_id}")
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
            files = {'file': (filename, f)}
            
            try:
                response = self._make_request(
                    'POST',
                    f'core/submission/{submission_id}/attachment',
                    files=files
                )
                logger.info(f"Uploaded attachment: {filename}")
                return response
            except Exception as e:
                logger.error(f"Failed to upload attachment: {e}")
                raise
    
    def add_message(self, submission_id: str, message: str) -> Dict:
        """Add a message to a submission."""
        payload = {
            "message": message
        }
        
        try:
            response = self._make_request(
                'POST',
                f'core/submission/{submission_id}/message',
                data=payload
            )
            logger.info(f"Added message to submission #{submission_id}")
            return response
        except Exception as e:
            logger.error(f"Failed to add message: {e}")
            raise
    
    def get_submission_status(self, submission_id: str) -> Dict:
        """Get submission status and details."""
        try:
            response = self._make_request('GET', f'core/submission/{submission_id}')
            
            status_info = {
                'id': response.get('submissionId'),
                'title': response.get('title'),
                'state': response.get('status', {}).get('name'),
                'severity': response.get('severity'),
                'created_at': response.get('createdAt'),
                'updated_at': response.get('updatedAt'),
                'bounty_awarded': response.get('bountyAmount') is not None
            }
            
            return status_info
        except Exception as e:
            logger.error(f"Failed to get submission status: {e}")
            raise
    
    def get_bounty_amount(self, submission_id: str) -> Optional[float]:
        """Get bounty amount if awarded."""
        try:
            response = self._make_request('GET', f'core/submission/{submission_id}')
            amount = response.get('bountyAmount')
            return float(amount) if amount else None
        except Exception as e:
            logger.error(f"Failed to get bounty amount: {e}")
            return None
    
    def get_vulnerability_types(self) -> List[Dict]:
        """Get list of vulnerability types with IDs."""
        try:
            response = self._make_request('GET', 'core/public/vulnerability-type')
            return response.get('records', [])
        except Exception as e:
            logger.error(f"Failed to get vulnerability types: {e}")
            return []
    
    def submit_complete_report(
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
        """
        Complete workflow: Create submission and add attachments.
        
        Args:
            program_id: Program ID
            title: Title
            description: Description
            severity: Severity (1-4)
            endpoint: Affected endpoint
            vulnerability_type_id: Vulnerability type ID
            steps_to_reproduce: Reproduction steps
            impact: Impact description
            proof_of_concept: PoC code
            attachments: File paths to attach
            
        Returns:
            Complete submission data
        """
        logger.info(f"Submitting report to Intigriti program {program_id}: {title}")
        
        # Step 1: Create submission
        submission = self.create_submission(
            program_id=program_id,
            title=title,
            description=description,
            severity=severity,
            endpoint=endpoint,
            vulnerability_type_id=vulnerability_type_id,
            steps_to_reproduce=steps_to_reproduce,
            impact=impact,
            proof_of_concept=proof_of_concept
        )
        
        submission_id = submission.get('submissionId')
        
        # Step 2: Upload attachments
        if attachments:
            for file_path in attachments:
                try:
                    self.upload_attachment(submission_id, file_path)
                except Exception as e:
                    logger.warning(f"Failed to upload {file_path}: {e}")
        
        logger.info(f"Successfully submitted Intigriti report #{submission_id}")
        
        return {
            'submission_id': submission_id,
            'program': program_id,
            'title': title,
            'severity': severity,
            'status': 'submitted',
            'created_at': submission.get('createdAt'),
            'url': f"https://app.intigriti.com/researcher/submissions/{submission_id}"
        }
    
    def map_severity_from_string(self, severity: str) -> int:
        """
        Map severity string to Intigriti severity integer.
        
        Args:
            severity: Severity string (critical, high, medium, low)
            
        Returns:
            Intigriti severity (1-4)
        """
        mapping = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return mapping.get(severity.lower(), 2)
    
    def estimate_payout(
        self,
        program_id: str,
        severity: int,
        vulnerability_type: str
    ) -> Dict[str, float]:
        """
        Estimate payout based on severity.
        
        Returns:
            Dict with 'min', 'max', 'avg' payout estimates in EUR
        """
        ranges = {
            4: {'min': 2000, 'max': 25000, 'avg': 8000},   # Critical
            3: {'min': 800, 'max': 8000, 'avg': 3000},     # High
            2: {'min': 250, 'max': 2500, 'avg': 1000},     # Medium
            1: {'min': 50, 'max': 500, 'avg': 200}         # Low
        }
        
        return ranges.get(severity, ranges[2])
