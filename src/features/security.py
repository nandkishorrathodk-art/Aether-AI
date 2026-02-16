import subprocess
import logging
import asyncio
import json
from typing import Dict, List, Optional
from src.config import settings

logger = logging.getLogger(__name__)

class SecurityModule:
    """
    Cybersecurity Professional Mode
    Handles SOC Analysis, PenTesting, and Threat Intel.
    """
    
    def __init__(self):
        self.nmap_available = self._check_nmap()

    def _check_nmap(self) -> bool:
        """Check if nmap is installed"""
        try:
            subprocess.run(["nmap", "--version"], capture_output=True)
            return True
        except FileNotFoundError:
            logger.warning("Nmap not found in PATH. Scanning features disabled.")
            return False

    async def run_scan(self, target: str, scan_type: str = "quick") -> str:
        """Run Nmap scan on target (Authorized Only)"""
        if not self.nmap_available:
            return "Error: Nmap is not installed or not in PATH."
            
        # Security: Basic sanitization
        if any(c in target for c in [";", "&", "|", "`", "$"]):
             return "Error: Invalid target format."

        cmd = ["nmap", target]
        if scan_type == "quick":
            cmd.extend(["-F", "-T4"])
        elif scan_type == "full":
            cmd.extend(["-p-", "-sV", "-T4"])
        elif scan_type == "vuln":
            cmd.extend(["--script", "vuln"])
            
        logger.info(f"Starting Nmap scan: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return f"Nmap Failed: {stderr.decode()}"
                
            return stdout.decode()
        except Exception as e:
            return f"Scan Execution Error: {str(e)}"

    async def analyze_logs(self, log_name: str = "Security", limit: int = 20) -> str:
        """Get Windows Event Logs via PowerShell"""
        ps_script = f"Get-WinEvent -LogName {log_name} -MaxEvents {limit} | Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json"
        
        try:
            process = await asyncio.create_subprocess_exec(
                "powershell", "-Command", ps_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                 # Check if it requires Admin
                 if "Access is denied" in stderr.decode():
                     return "Error: Access Denied. Please run Aether as Administrator to read Security logs."
                 return f"Log Retrieval Failed: {stderr.decode()}"
            
            try:
                logs = json.loads(stdout.decode())
                # Format for LLM
                summary = f"Recent {limit} events from {log_name}:\n"
                if isinstance(logs, dict): logs = [logs] # Handle single event
                
                for log in logs:
                    summary += f"[{log['TimeCreated']}] EventID: {log['Id']} ({log['LevelDisplayName']}) - {log['Message'][:100]}...\n"
                return summary
            except json.JSONDecodeError:
                return f"Failed to parse logs: {stdout.decode()[:200]}"
                
        except Exception as e:
            return f"Log Analysis Error: {str(e)}"

    async def check_ip_reputation(self, ip: str) -> str:
        """Check IP against Threat Intel APIs (Placeholder)"""
        # TODO: Implement VirusTotal / AbuseIPDB with API keys
        return f"Reputation check for {ip}: APIs not configured yet."

security_module = SecurityModule()
