"""
Security Tool Integrations
Integrations with Metasploit, Nessus, OWASP ZAP, and other security tools
"""

import json
import requests
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
import subprocess
import logging
import asyncio

logger = logging.getLogger(__name__)


class ScanTool(str, Enum):
    """Supported security scanning tools"""
    METASPLOIT = "metasploit"
    NESSUS = "nessus"
    ZAP = "zap"
    NUCLEI = "nuclei"
    NIKTO = "nikto"


@dataclass
class ScanResult:
    """Scan result from security tool"""
    tool: ScanTool
    target: str
    vulnerabilities_found: int
    scan_duration: float
    findings: List[Dict[str, Any]]
    raw_output: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "tool": self.tool.value,
            "target": self.target,
            "vulnerabilities_found": self.vulnerabilities_found,
            "scan_duration": self.scan_duration,
            "findings": self.findings
        }


class MetasploitIntegration:
    """
    Metasploit Framework Integration
    
    Features:
    - Module search and execution
    - Exploit framework integration
    - Automated exploitation
    - Payload generation
    """
    
    def __init__(self, msf_rpc_host: str = "127.0.0.1", msf_rpc_port: int = 55553):
        """Initialize Metasploit integration"""
        self.rpc_host = msf_rpc_host
        self.rpc_port = msf_rpc_port
        self.rpc_url = f"http://{msf_rpc_host}:{msf_rpc_port}/api/"
        self.token = None
        logger.info("Metasploit integration initialized")
    
    async def connect(self, username: str = "msf", password: str = "msf"):
        """
        Connect to Metasploit RPC server
        
        Args:
            username: MSF RPC username
            password: MSF RPC password
        
        Returns:
            True if connected successfully
        """
        try:
            response = requests.post(
                f"{self.rpc_url}auth/login",
                json={"username": username, "password": password},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("token")
                logger.info("Connected to Metasploit RPC")
                return True
        except Exception as e:
            logger.error(f"Failed to connect to Metasploit: {e}")
        
        return False
    
    async def search_exploits(self, keyword: str) -> List[Dict[str, str]]:
        """
        Search for Metasploit modules
        
        Args:
            keyword: Search keyword
        
        Returns:
            List of matching modules
        """
        if not self.token:
            logger.warning("Not connected to Metasploit RPC")
            return []
        
        try:
            response = requests.post(
                f"{self.rpc_url}module/search",
                json={"token": self.token, "query": keyword},
                timeout=30
            )
            
            if response.status_code == 200:
                modules = response.json().get("modules", [])
                logger.info(f"Found {len(modules)} Metasploit modules for '{keyword}'")
                return modules
        except Exception as e:
            logger.error(f"Module search failed: {e}")
        
        return []
    
    async def execute_module(
        self,
        module_type: str,
        module_name: str,
        options: Dict[str, str]
    ) -> Optional[Dict[str, Any]]:
        """
        Execute Metasploit module
        
        Args:
            module_type: Module type (exploit, auxiliary, post, etc.)
            module_name: Full module name
            options: Module options
        
        Returns:
            Execution result
        """
        if not self.token:
            logger.warning("Not connected to Metasploit RPC")
            return None
        
        try:
            response = requests.post(
                f"{self.rpc_url}module/execute",
                json={
                    "token": self.token,
                    "module_type": module_type,
                    "module_name": module_name,
                    "options": options
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Module executed: {module_name}")
                return result
        except Exception as e:
            logger.error(f"Module execution failed: {e}")
        
        return None


class NessusIntegration:
    """
    Nessus Professional Integration
    
    Features:
    - Automated vulnerability scanning
    - Scan template management
    - Report generation
    - Compliance checking
    """
    
    def __init__(self, nessus_url: str = "https://localhost:8834", api_key: str = None, secret_key: str = None):
        """Initialize Nessus integration"""
        self.nessus_url = nessus_url.rstrip('/')
        self.api_key = api_key
        self.secret_key = secret_key
        self.headers = {
            "X-ApiKeys": f"accessKey={api_key}; secretKey={secret_key}" if api_key and secret_key else None
        }
        logger.info("Nessus integration initialized")
    
    async def create_scan(
        self,
        name: str,
        targets: List[str],
        template: str = "basic"
    ) -> Optional[int]:
        """
        Create new Nessus scan
        
        Args:
            name: Scan name
            targets: List of target IPs/hosts
            template: Scan template name
        
        Returns:
            Scan ID if created successfully
        """
        try:
            response = requests.post(
                f"{self.nessus_url}/scans",
                headers=self.headers,
                json={
                    "uuid": template,
                    "settings": {
                        "name": name,
                        "text_targets": ",".join(targets)
                    }
                },
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                scan_id = response.json()["scan"]["id"]
                logger.info(f"Created Nessus scan: {scan_id}")
                return scan_id
        except Exception as e:
            logger.error(f"Failed to create Nessus scan: {e}")
        
        return None
    
    async def launch_scan(self, scan_id: int) -> bool:
        """Launch Nessus scan"""
        try:
            response = requests.post(
                f"{self.nessus_url}/scans/{scan_id}/launch",
                headers=self.headers,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Launched Nessus scan: {scan_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to launch scan: {e}")
        
        return False
    
    async def get_scan_results(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get Nessus scan results"""
        try:
            response = requests.get(
                f"{self.nessus_url}/scans/{scan_id}",
                headers=self.headers,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                results = response.json()
                logger.info(f"Retrieved Nessus scan results: {scan_id}")
                return results
        except Exception as e:
            logger.error(f"Failed to get scan results: {e}")
        
        return None


class ZAPIntegration:
    """
    OWASP ZAP Integration
    
    Features:
    - Spider/crawler
    - Active scanning
    - Passive scanning
    - Ajax spidering
    """
    
    def __init__(self, zap_url: str = "http://localhost:8080", api_key: str = None):
        """Initialize ZAP integration"""
        self.zap_url = zap_url.rstrip('/')
        self.api_key = api_key
        self.base_params = {"apikey": api_key} if api_key else {}
        logger.info("OWASP ZAP integration initialized")
    
    async def spider_scan(self, target_url: str, max_depth: int = 5) -> Optional[int]:
        """
        Start spider scan
        
        Args:
            target_url: Target URL
            max_depth: Maximum crawl depth
        
        Returns:
            Scan ID if started successfully
        """
        try:
            params = {**self.base_params, "url": target_url, "maxChildren": max_depth}
            response = requests.get(
                f"{self.zap_url}/JSON/spider/action/scan/",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                scan_id = response.json().get("scan")
                logger.info(f"Started ZAP spider scan: {scan_id}")
                return scan_id
        except Exception as e:
            logger.error(f"Failed to start spider scan: {e}")
        
        return None
    
    async def active_scan(self, target_url: str) -> Optional[int]:
        """
        Start active scan
        
        Args:
            target_url: Target URL
        
        Returns:
            Scan ID if started successfully
        """
        try:
            params = {**self.base_params, "url": target_url}
            response = requests.get(
                f"{self.zap_url}/JSON/ascan/action/scan/",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                scan_id = response.json().get("scan")
                logger.info(f"Started ZAP active scan: {scan_id}")
                return scan_id
        except Exception as e:
            logger.error(f"Failed to start active scan: {e}")
        
        return None
    
    async def get_alerts(self, target_url: str = None) -> List[Dict[str, Any]]:
        """
        Get ZAP alerts (findings)
        
        Args:
            target_url: Optional target URL filter
        
        Returns:
            List of alerts
        """
        try:
            params = self.base_params.copy()
            if target_url:
                params["baseurl"] = target_url
            
            response = requests.get(
                f"{self.zap_url}/JSON/core/view/alerts/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                alerts = response.json().get("alerts", [])
                logger.info(f"Retrieved {len(alerts)} ZAP alerts")
                return alerts
        except Exception as e:
            logger.error(f"Failed to get ZAP alerts: {e}")
        
        return []


class NucleiIntegration:
    """
    Nuclei Integration
    
    Features:
    - Template-based scanning
    - Custom template support
    - High-speed scanning
    """
    
    def __init__(self, nuclei_path: str = "nuclei"):
        """Initialize Nuclei integration"""
        self.nuclei_path = nuclei_path
        logger.info("Nuclei integration initialized")
    
    async def scan(
        self,
        target: str,
        templates: List[str] = None,
        severity: List[str] = None,
        output_file: str = None
    ) -> Optional[str]:
        """
        Run Nuclei scan
        
        Args:
            target: Target URL or IP
            templates: List of template paths
            severity: Severity levels to scan (critical, high, medium, low, info)
            output_file: Output file path
        
        Returns:
            Scan output
        """
        cmd = [self.nuclei_path, "-target", target, "-json"]
        
        if templates:
            cmd.extend(["-t", ",".join(templates)])
        
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        if output_file:
            cmd.extend(["-o", output_file])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            logger.info(f"Nuclei scan completed for {target}")
            return result.stdout
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
        
        return None


class SecurityToolOrchestrator:
    """
    Orchestrates multiple security tools for comprehensive scanning
    """
    
    def __init__(self):
        """Initialize tool orchestrator"""
        self.metasploit = MetasploitIntegration()
        self.nessus = NessusIntegration()
        self.zap = ZAPIntegration()
        self.nuclei = NucleiIntegration()
        logger.info("Security Tool Orchestrator initialized")
    
    async def comprehensive_scan(
        self,
        target_url: str,
        tools: List[ScanTool] = None
    ) -> Dict[str, ScanResult]:
        """
        Run comprehensive scan using multiple tools
        
        Args:
            target_url: Target URL
            tools: List of tools to use (default: all available)
        
        Returns:
            Results from each tool
        """
        if tools is None:
            tools = [ScanTool.ZAP, ScanTool.NUCLEI]
        
        results = {}
        
        if ScanTool.ZAP in tools:
            try:
                spider_id = await self.zap.spider_scan(target_url)
                if spider_id:
                    await asyncio.sleep(30)
                    scan_id = await self.zap.active_scan(target_url)
                    if scan_id:
                        await asyncio.sleep(60)
                        alerts = await self.zap.get_alerts(target_url)
                        
                        results[ScanTool.ZAP] = ScanResult(
                            tool=ScanTool.ZAP,
                            target=target_url,
                            vulnerabilities_found=len(alerts),
                            scan_duration=90.0,
                            findings=alerts
                        )
            except Exception as e:
                logger.error(f"ZAP scan failed: {e}")
        
        if ScanTool.NUCLEI in tools:
            try:
                output = await self.nuclei.scan(
                    target=target_url,
                    severity=["critical", "high", "medium"]
                )
                
                if output:
                    findings = []
                    for line in output.strip().split('\n'):
                        if line:
                            try:
                                findings.append(json.loads(line))
                            except:
                                pass
                    
                    results[ScanTool.NUCLEI] = ScanResult(
                        tool=ScanTool.NUCLEI,
                        target=target_url,
                        vulnerabilities_found=len(findings),
                        scan_duration=0.0,
                        findings=findings
                    )
            except Exception as e:
                logger.error(f"Nuclei scan failed: {e}")
        
        logger.info(f"Comprehensive scan completed for {target_url}")
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        return {
            "tools_available": [
                "Metasploit",
                "Nessus",
                "OWASP ZAP",
                "Nuclei",
                "Nikto"
            ],
            "orchestrator_status": "ready"
        }
