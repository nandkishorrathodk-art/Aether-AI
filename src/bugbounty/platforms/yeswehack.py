import requests
import os
from typing import Dict, List, Optional
from pathlib import Path
from src.utils.logger import get_logger

logger = get_logger(__name__)


class YesWeHackClient:
    """
    YesWeHack API client for automated bug bounty report submission.
    
    API Documentation: https://api.yeswehack.com/
    """
    
    BASE_URL = "https://api.yeswehack.com"
    
    def __init__(self, api_token: str):
        """
        Initialize YesWeHack client with API credentials.
        
        Args:
            api_token: YesWeHack API token (from Settings > API)
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
            logger.error(f"YesWeHack API request failed: {e}")
            raise Exception(f"YesWeHack API error: {str(e)}")
    
    def get_programs(self) -> List[Dict]:
        """Get list of available programs."""
        try:
            response = self._make_request('GET', 'programs')
            return response.get('items', [])
        except Exception as e:
            logger.error(f"Failed to get programs: {e}")
            return []
    
    def get_program(self, program_slug: str) -> Optional[Dict]:
        """Get program details by slug."""
        try:
            response = self._make_request('GET', f'programs/{program_slug}')
            return response
        except Exception as e:
            logger.error(f"Failed to get program {program_slug}: {e}")
            return None
    
    def create_report(
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
        remediation_advice: Optional[str] = None
    ) -> Dict:
        """
        Create a new report.
        
        Args:
            program_slug: Program slug
            title: Report title
            description: Detailed description
            severity: Severity (critical, high, medium, low, info)
            cvss_vector: CVSS vector string (optional)
            vulnerability_type: Vulnerability type
            affected_assets: List of affected URLs/assets
            steps_to_reproduce: Reproduction steps
            impact_description: Impact description
            remediation_advice: Remediation recommendation
            
        Returns:
            Report data with ID
        """
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "hunter_assessment": cvss_vector,
            "vulnerability_type": vulnerability_type,
            "scope": affected_assets[0] if affected_assets else "",
            "poc": steps_to_reproduce,
            "impact": impact_description
        }
        
        if remediation_advice:
            payload["remediation"] = remediation_advice
        
        try:
            response = self._make_request(
                'POST',
                f'programs/{program_slug}/reports',
                data=payload
            )
            report_id = response.get('report_id')
            logger.info(f"Created YesWeHack report #{report_id} for {program_slug}")
            return response
        except Exception as e:
            logger.error(f"Failed to create report: {e}")
            raise
    
    def upload_attachment(self, report_id: str, file_path: str) -> Dict:
        """
        Upload an attachment to a report.
        
        Args:
            report_id: Report ID
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
                    f'reports/{report_id}/attachments',
                    files=files
                )
                logger.info(f"Uploaded attachment: {filename}")
                return response
            except Exception as e:
                logger.error(f"Failed to upload attachment: {e}")
                raise
    
    def add_comment(self, report_id: str, comment: str) -> Dict:
        """Add a comment to a report."""
        payload = {
            "comment": comment
        }
        
        try:
            response = self._make_request(
                'POST',
                f'reports/{report_id}/comments',
                data=payload
            )
            logger.info(f"Added comment to report #{report_id}")
            return response
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            raise
    
    def get_report_status(self, report_id: str) -> Dict:
        """Get report status and details."""
        try:
            response = self._make_request('GET', f'reports/{report_id}')
            
            status_info = {
                'id': response.get('report_id'),
                'title': response.get('title'),
                'state': response.get('status'),
                'severity': response.get('severity'),
                'created_at': response.get('created_at'),
                'updated_at': response.get('updated_at'),
                'bounty_awarded': response.get('bounty') is not None
            }
            
            return status_info
        except Exception as e:
            logger.error(f"Failed to get report status: {e}")
            raise
    
    def get_bounty_amount(self, report_id: str) -> Optional[float]:
        """Get bounty amount if awarded."""
        try:
            response = self._make_request('GET', f'reports/{report_id}')
            bounty = response.get('bounty')
            return float(bounty['amount']) if bounty else None
        except Exception as e:
            logger.error(f"Failed to get bounty amount: {e}")
            return None
    
    def submit_complete_report(
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
        """
        Complete workflow: Create report and add PoC/attachments.
        
        Args:
            program_slug: Program slug
            title: Title
            description: Description
            severity: Severity
            cvss_vector: CVSS vector
            vulnerability_type: Vulnerability type
            affected_assets: Affected URLs/assets
            steps_to_reproduce: Reproduction steps
            impact_description: Impact
            proof_of_concept: PoC code
            attachments: File paths to attach
            remediation_advice: Remediation recommendation
            
        Returns:
            Complete report data
        """
        logger.info(f"Submitting report to YesWeHack {program_slug}: {title}")
        
        # Step 1: Create report
        report = self.create_report(
            program_slug=program_slug,
            title=title,
            description=description,
            severity=severity,
            cvss_vector=cvss_vector,
            vulnerability_type=vulnerability_type,
            affected_assets=affected_assets,
            steps_to_reproduce=steps_to_reproduce,
            impact_description=impact_description,
            remediation_advice=remediation_advice
        )
        
        report_id = report.get('report_id')
        
        # Step 2: Upload attachments
        if attachments:
            for file_path in attachments:
                try:
                    self.upload_attachment(report_id, file_path)
                except Exception as e:
                    logger.warning(f"Failed to upload {file_path}: {e}")
        
        # Step 3: Add PoC as comment
        if proof_of_concept:
            poc_comment = f"## Proof of Concept\n\n```\n{proof_of_concept}\n```"
            try:
                self.add_comment(report_id, poc_comment)
            except Exception as e:
                logger.warning(f"Failed to add PoC comment: {e}")
        
        logger.info(f"Successfully submitted YesWeHack report #{report_id}")
        
        return {
            'report_id': report_id,
            'program': program_slug,
            'title': title,
            'severity': severity,
            'status': 'submitted',
            'created_at': report.get('created_at'),
            'url': f"https://yeswehack.com/programs/{program_slug}/reports/{report_id}"
        }
    
    def estimate_payout(
        self,
        program_slug: str,
        severity: str,
        vulnerability_type: str
    ) -> Dict[str, float]:
        """
        Estimate payout based on severity.
        
        Returns:
            Dict with 'min', 'max', 'avg' payout estimates in EUR
        """
        ranges = {
            'critical': {'min': 2500, 'max': 20000, 'avg': 7500},
            'high': {'min': 1000, 'max': 7500, 'avg': 3000},
            'medium': {'min': 300, 'max': 2500, 'avg': 1000},
            'low': {'min': 100, 'max': 500, 'avg': 250},
            'info': {'min': 0, 'max': 100, 'avg': 25}
        }
        
        return ranges.get(severity.lower(), ranges['info'])
