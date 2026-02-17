import requests
import os
from typing import Dict, List, Optional, Any
from pathlib import Path
import base64
from src.utils.logger import get_logger

logger = get_logger(__name__)


class HackerOneClient:
    """
    HackerOne API client for automated bug bounty report submission.
    
    API Documentation: https://api.hackerone.com/
    """
    
    BASE_URL = "https://api.hackerone.com/v1"
    
    def __init__(self, username: str, api_token: str):
        """
        Initialize HackerOne client with API credentials.
        
        Args:
            username: HackerOne username
            api_token: HackerOne API token (from Settings > API Tokens)
        """
        self.username = username
        self.api_token = api_token
        self.session = requests.Session()
        self.session.auth = (username, api_token)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict:
        """Make authenticated API request."""
        url = f"{self.BASE_URL}/{endpoint}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"HackerOne API request failed: {e}")
            raise Exception(f"HackerOne API error: {str(e)}")
    
    def get_programs(self) -> List[Dict]:
        """Get list of programs accessible to the user."""
        try:
            response = self._make_request('GET', 'hackers/programs')
            return response.get('data', [])
        except Exception as e:
            logger.error(f"Failed to get programs: {e}")
            return []
    
    def get_program(self, program_handle: str) -> Optional[Dict]:
        """Get program details by handle."""
        try:
            response = self._make_request('GET', f'hackers/programs/{program_handle}')
            return response.get('data')
        except Exception as e:
            logger.error(f"Failed to get program {program_handle}: {e}")
            return None
    
    def create_report(
        self,
        program_handle: str,
        title: str,
        vulnerability_type: str,
        severity: str,
        description: str,
        steps_to_reproduce: str,
        impact: str,
        weakness_id: Optional[int] = None,
        structured_scope_id: Optional[str] = None
    ) -> Dict:
        """
        Create a new vulnerability report.
        
        Args:
            program_handle: Program handle (e.g., 'security')
            title: Report title
            vulnerability_type: Type of vulnerability (e.g., 'sql_injection', 'xss')
            severity: Severity rating (e.g., 'critical', 'high', 'medium', 'low')
            description: Detailed description
            steps_to_reproduce: Steps to reproduce the vulnerability
            impact: Impact description
            weakness_id: CWE ID (optional)
            structured_scope_id: Scope ID from program (optional)
            
        Returns:
            Report data with ID
        """
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": program_handle,
                    "title": title,
                    "vulnerability_information": description,
                    "severity_rating": severity,
                    "impact": impact
                }
            }
        }
        
        # Add weakness if provided
        if weakness_id:
            payload["data"]["attributes"]["weakness_id"] = weakness_id
        
        # Add structured scope if provided
        if structured_scope_id:
            payload["data"]["relationships"] = {
                "structured_scope": {
                    "data": {
                        "type": "structured-scope",
                        "id": structured_scope_id
                    }
                }
            }
        
        try:
            response = self._make_request('POST', 'reports', data=payload)
            report_id = response['data']['id']
            logger.info(f"Created HackerOne report #{report_id} for {program_handle}")
            return response['data']
        except Exception as e:
            logger.error(f"Failed to create report: {e}")
            raise
    
    def upload_attachment(self, file_path: str) -> str:
        """
        Upload an attachment (screenshot, PoC file, etc.).
        
        Args:
            file_path: Path to file to upload
            
        Returns:
            Attachment ID
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read file and encode to base64
        with open(file_path, 'rb') as f:
            file_data = f.read()
            encoded = base64.b64encode(file_data).decode('utf-8')
        
        filename = Path(file_path).name
        
        payload = {
            "data": {
                "type": "attachment",
                "attributes": {
                    "filename": filename,
                    "content": encoded
                }
            }
        }
        
        try:
            response = self._make_request('POST', 'attachments', data=payload)
            attachment_id = response['data']['id']
            logger.info(f"Uploaded attachment: {filename} (ID: {attachment_id})")
            return attachment_id
        except Exception as e:
            logger.error(f"Failed to upload attachment: {e}")
            raise
    
    def add_comment_to_report(
        self,
        report_id: str,
        message: str,
        attachment_ids: Optional[List[str]] = None
    ) -> Dict:
        """
        Add a comment to a report (useful for adding PoC, additional info).
        
        Args:
            report_id: Report ID
            message: Comment text
            attachment_ids: List of attachment IDs to include
            
        Returns:
            Activity data
        """
        payload = {
            "data": {
                "type": "activity-comment",
                "attributes": {
                    "message": message
                }
            }
        }
        
        if attachment_ids:
            payload["data"]["relationships"] = {
                "attachments": {
                    "data": [
                        {"type": "attachment", "id": att_id}
                        for att_id in attachment_ids
                    ]
                }
            }
        
        try:
            response = self._make_request(
                'POST',
                f'reports/{report_id}/activities',
                data=payload
            )
            logger.info(f"Added comment to report #{report_id}")
            return response['data']
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            raise
    
    def get_report_status(self, report_id: str) -> Dict:
        """
        Get report status and details.
        
        Args:
            report_id: Report ID
            
        Returns:
            Report data including status
        """
        try:
            response = self._make_request('GET', f'reports/{report_id}')
            report = response['data']
            
            status_info = {
                'id': report['id'],
                'title': report['attributes']['title'],
                'state': report['attributes']['state'],
                'created_at': report['attributes']['created_at'],
                'triaged_at': report['attributes'].get('triaged_at'),
                'closed_at': report['attributes'].get('closed_at'),
                'bounty_awarded': report['attributes'].get('bounty_awarded_at') is not None,
                'severity': report['attributes'].get('severity_rating')
            }
            
            return status_info
        except Exception as e:
            logger.error(f"Failed to get report status: {e}")
            raise
    
    def get_bounty_amount(self, report_id: str) -> Optional[float]:
        """
        Get bounty amount if awarded.
        
        Args:
            report_id: Report ID
            
        Returns:
            Bounty amount in USD or None
        """
        try:
            response = self._make_request('GET', f'reports/{report_id}')
            bounties = response['data'].get('relationships', {}).get('bounties', {}).get('data', [])
            
            if bounties:
                # Get first bounty amount
                bounty_id = bounties[0]['id']
                bounty_response = self._make_request('GET', f'bounties/{bounty_id}')
                amount = bounty_response['data']['attributes']['amount']
                return float(amount)
            
            return None
        except Exception as e:
            logger.error(f"Failed to get bounty amount: {e}")
            return None
    
    def submit_complete_report(
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
        """
        Complete workflow: Create report and add PoC/attachments.
        
        This is the main method you'll use for automated submission.
        
        Args:
            program_handle: Program handle
            title: Report title
            vulnerability_type: Vulnerability type
            severity: Severity (critical, high, medium, low)
            description: Detailed description
            steps_to_reproduce: Reproduction steps
            impact: Impact description
            proof_of_concept: PoC code/script (optional)
            attachments: List of file paths to attach (screenshots, etc.)
            weakness_id: CWE ID (optional)
            
        Returns:
            Complete report data with ID and status
        """
        logger.info(f"Submitting report to {program_handle}: {title}")
        
        # Step 1: Create the report
        report = self.create_report(
            program_handle=program_handle,
            title=title,
            vulnerability_type=vulnerability_type,
            severity=severity,
            description=description,
            steps_to_reproduce=steps_to_reproduce,
            impact=impact,
            weakness_id=weakness_id
        )
        
        report_id = report['id']
        
        # Step 2: Upload attachments if provided
        attachment_ids = []
        if attachments:
            for file_path in attachments:
                try:
                    att_id = self.upload_attachment(file_path)
                    attachment_ids.append(att_id)
                except Exception as e:
                    logger.warning(f"Failed to upload {file_path}: {e}")
        
        # Step 3: Add PoC as comment if provided
        if proof_of_concept or attachment_ids:
            poc_message = "## Proof of Concept\n\n"
            if proof_of_concept:
                poc_message += f"```\n{proof_of_concept}\n```\n\n"
            if attachment_ids:
                poc_message += "See attached files for additional evidence."
            
            try:
                self.add_comment_to_report(
                    report_id=report_id,
                    message=poc_message,
                    attachment_ids=attachment_ids if attachment_ids else None
                )
            except Exception as e:
                logger.warning(f"Failed to add PoC comment: {e}")
        
        logger.info(f"Successfully submitted report #{report_id}")
        
        return {
            'report_id': report_id,
            'program': program_handle,
            'title': title,
            'severity': severity,
            'status': 'submitted',
            'created_at': report.get('attributes', {}).get('created_at'),
            'url': f"https://hackerone.com/reports/{report_id}"
        }
    
    def get_vulnerability_types(self) -> List[str]:
        """Get list of supported vulnerability types."""
        return [
            'sql_injection',
            'xss',
            'csrf',
            'authentication_bypass',
            'authorization_bypass',
            'information_disclosure',
            'remote_code_execution',
            'server_side_request_forgery',
            'xml_external_entity',
            'insecure_direct_object_reference',
            'security_misconfiguration',
            'broken_authentication',
            'sensitive_data_exposure',
            'missing_function_level_access_control',
            'cross_site_request_forgery',
            'using_components_with_known_vulnerabilities',
            'unvalidated_redirects_and_forwards',
            'clickjacking',
            'api_abuse',
            'denial_of_service'
        ]
    
    def estimate_payout(
        self,
        program_handle: str,
        severity: str,
        vulnerability_type: str
    ) -> Dict[str, float]:
        """
        Estimate payout based on program bounty table and severity.
        
        Note: This is an approximation based on typical bounty ranges.
        Actual payout depends on impact, quality, and program specifics.
        
        Returns:
            Dict with 'min', 'max', 'avg' payout estimates in USD
        """
        # Typical HackerOne bounty ranges by severity
        ranges = {
            'critical': {'min': 5000, 'max': 50000, 'avg': 15000},
            'high': {'min': 2000, 'max': 20000, 'avg': 7500},
            'medium': {'min': 500, 'max': 5000, 'avg': 2000},
            'low': {'min': 100, 'max': 1000, 'avg': 400},
            'none': {'min': 0, 'max': 200, 'avg': 50}
        }
        
        return ranges.get(severity.lower(), ranges['none'])
