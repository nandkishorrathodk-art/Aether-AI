"""
Nuclei Scanner Integration for Aether AI
Professional vulnerability scanner with 5000+ templates
"""
import asyncio
import json
import subprocess
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime

from src.utils.logger import get_logger

logger = get_logger(__name__)


class NucleiScanner:
    """
    Nuclei vulnerability scanner integration.
    
    Features:
    - 5000+ vulnerability templates
    - Fast parallel scanning
    - Custom template support
    - JSON output parsing
    - Severity filtering
    """
    
    def __init__(self, nuclei_path: Optional[str] = None):
        """
        Initialize Nuclei scanner.
        
        Args:
            nuclei_path: Path to nuclei binary (default: searches in PATH)
        """
        self.nuclei_path = nuclei_path or "nuclei"
        self.templates_dir = Path.home() / "nuclei-templates"
        
        logger.info("Nuclei Scanner initialized")
    
    async def check_installation(self) -> bool:
        """
        Check if Nuclei is installed.
        
        Returns:
            True if Nuclei is available
        """
        try:
            result = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            return result.returncode == 0
        
        except FileNotFoundError:
            logger.error("Nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return False
        
        except Exception as e:
            logger.error(f"Error checking Nuclei: {e}")
            return False
    
    async def update_templates(self) -> bool:
        """
        Update Nuclei templates to latest version.
        
        Returns:
            True if update successful
        """
        try:
            logger.info("Updating Nuclei templates...")
            
            process = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info("Nuclei templates updated successfully")
                return True
            else:
                logger.error(f"Template update failed: {stderr.decode()}")
                return False
        
        except Exception as e:
            logger.error(f"Error updating templates: {e}")
            return False
    
    async def scan_target(
        self,
        target: str,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        templates: Optional[List[str]] = None,
        rate_limit: int = 150,
        timeout: int = 300
    ) -> Dict:
        """
        Scan target with Nuclei.
        
        Args:
            target: Target URL or domain
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags (e.g., sqli, xss, rce)
            templates: Specific template paths to use
            rate_limit: Requests per second
            timeout: Scan timeout in seconds
        
        Returns:
            Scan results dictionary
        """
        try:
            logger.info(f"Starting Nuclei scan on {target}")
            
            # Build command
            cmd = [
                self.nuclei_path,
                "-target", target,
                "-json",
                "-rate-limit", str(rate_limit),
                "-timeout", str(timeout),
                "-silent"
            ]
            
            # Add severity filter
            if severity:
                cmd.extend(["-severity", ",".join(severity)])
            
            # Add tags filter
            if tags:
                cmd.extend(["-tags", ",".join(tags)])
            
            # Add custom templates
            if templates:
                for template in templates:
                    cmd.extend(["-t", template])
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            results = []
            if stdout:
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            
            # Build response
            return {
                "success": True,
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities_found": len(results),
                "vulnerabilities": results,
                "scan_options": {
                    "severity": severity,
                    "tags": tags,
                    "templates": templates
                }
            }
        
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
            return {
                "success": False,
                "error": str(e),
                "target": target
            }
    
    async def scan_with_template(
        self,
        target: str,
        template_path: str
    ) -> Dict:
        """
        Scan target with specific template.
        
        Args:
            target: Target URL
            template_path: Path to custom template
        
        Returns:
            Scan results
        """
        return await self.scan_target(
            target=target,
            templates=[template_path]
        )
    
    async def get_available_tags(self) -> List[str]:
        """
        Get list of available template tags.
        
        Returns:
            List of tags
        """
        common_tags = [
            # Vulnerability types
            "sqli", "xss", "rce", "lfi", "rfi", "ssrf", "ssti",
            "xxe", "csrf", "idor", "redirect", "traversal",
            
            # Technologies
            "apache", "nginx", "wordpress", "joomla", "drupal",
            "php", "python", "nodejs", "java", "asp",
            
            # CVE-based
            "cve", "cve2021", "cve2022", "cve2023", "cve2024",
            
            # Security
            "misconfig", "exposure", "default-login", "unauth",
            "takeover", "file-upload", "backup"
        ]
        
        return common_tags
    
    async def scan_multiple_targets(
        self,
        targets: List[str],
        **scan_options
    ) -> Dict:
        """
        Scan multiple targets concurrently.
        
        Args:
            targets: List of target URLs
            **scan_options: Options to pass to scan_target()
        
        Returns:
            Combined scan results
        """
        logger.info(f"Scanning {len(targets)} targets...")
        
        # Create scan tasks
        tasks = []
        for target in targets:
            tasks.append(self.scan_target(target, **scan_options))
        
        # Run scans concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        all_vulnerabilities = []
        total_found = 0
        
        for result in results:
            if isinstance(result, dict) and result.get("success"):
                all_vulnerabilities.extend(result.get("vulnerabilities", []))
                total_found += result.get("vulnerabilities_found", 0)
        
        return {
            "success": True,
            "targets_scanned": len(targets),
            "total_vulnerabilities": total_found,
            "vulnerabilities": all_vulnerabilities
        }
    
    def parse_vulnerability(self, vuln: Dict) -> Dict:
        """
        Parse Nuclei vulnerability to standardized format.
        
        Args:
            vuln: Raw Nuclei vulnerability
        
        Returns:
            Standardized vulnerability dict
        """
        return {
            "title": vuln.get("info", {}).get("name", "Unknown"),
            "description": vuln.get("info", {}).get("description", ""),
            "severity": vuln.get("info", {}).get("severity", "unknown").upper(),
            "tags": vuln.get("info", {}).get("tags", []),
            "type": vuln.get("type", "unknown"),
            "matched_at": vuln.get("matched-at", ""),
            "extracted_results": vuln.get("extracted-results", []),
            "curl_command": vuln.get("curl-command", ""),
            "template_id": vuln.get("template-id", ""),
            "template_path": vuln.get("template", ""),
            "timestamp": vuln.get("timestamp", "")
        }


# Global instance
_nuclei_scanner = None

async def get_nuclei_scanner() -> NucleiScanner:
    """Get global Nuclei scanner instance."""
    global _nuclei_scanner
    if _nuclei_scanner is None:
        _nuclei_scanner = NucleiScanner()
        
        # Check installation
        if not await _nuclei_scanner.check_installation():
            logger.warning("Nuclei not installed. Some features will be unavailable.")
    
    return _nuclei_scanner
