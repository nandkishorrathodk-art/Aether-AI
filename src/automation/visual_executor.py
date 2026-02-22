"""
Visual Live Executor - Opens REAL windows for live viewing
Shows everything happening in real-time like a human would work

Features:
- Opens actual CMD/PowerShell windows (not background)
- Launches BurpSuite GUI
- Real-time progress streaming to dashboard
- Shows commands executing LIVE
"""

import asyncio
import subprocess
import os
import time
from typing import Optional, Dict, Any, Callable
from pathlib import Path
import json

from src.utils.logger import get_logger

logger = get_logger(__name__)


class VisualExecutor:
    """
    Visual Live Executor - Opens real terminal windows
    Everything visible like a human working
    """
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        """
        Args:
            progress_callback: Function to call with progress updates
                              Signature: callback(message: str, progress: float)
        """
        self.progress_callback = progress_callback
        self.active_processes: Dict[str, subprocess.Popen] = {}
        
        # Common tool paths
        self.burpsuite_path = self._find_burpsuite()
        self.nuclei_path = self._find_nuclei()
        
    def _find_burpsuite(self) -> Optional[str]:
        """Find BurpSuite installation"""
        common_paths = [
            r"C:\Program Files\BurpSuitePro\burpsuite_pro.exe",
            r"C:\Program Files\BurpSuite\burpsuite_community.exe",
            r"C:\Program Files (x86)\BurpSuitePro\burpsuite_pro.exe",
            r"C:\Users\{username}\AppData\Local\Programs\BurpSuite\burpsuite_community.exe".format(
                username=os.getenv("USERNAME")
            ),
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _find_nuclei(self) -> Optional[str]:
        """Find Nuclei installation"""
        # Check if nuclei is in PATH
        result = subprocess.run(
            ["where", "nuclei"],
            capture_output=True,
            text=True,
            shell=True
        )
        
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
        
        return None
    
    async def _update_progress(self, message: str, progress: float):
        """Send progress update to callback"""
        if self.progress_callback:
            try:
                if asyncio.iscoroutinefunction(self.progress_callback):
                    await self.progress_callback(message, progress)
                else:
                    self.progress_callback(message, progress)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")
    
    async def open_cmd_window(self, 
                             command: str, 
                             title: str = "Aether AI Live Execution",
                             stay_open: bool = True) -> Dict[str, Any]:
        """
        Open REAL CMD window that stays visible
        
        Args:
            command: Command to execute
            title: Window title
            stay_open: Keep window open after command finishes
        
        Returns:
            Dict with process info
        """
        try:
            await self._update_progress(f"Opening CMD window: {title}", 0.1)
            
            # Build CMD command that stays open
            if stay_open:
                full_command = f'start "{title}" cmd /K "{command}"'
            else:
                full_command = f'start "{title}" cmd /C "{command}"'
            
            logger.info(f"Executing: {full_command}")
            
            # Execute with shell=True to use 'start' command
            process = subprocess.Popen(
                full_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Store process
            process_id = f"cmd_{int(time.time())}"
            self.active_processes[process_id] = process
            
            await self._update_progress(f"CMD window opened: {title}", 1.0)
            
            return {
                "success": True,
                "process_id": process_id,
                "pid": process.pid,
                "title": title,
                "command": command
            }
        
        except Exception as e:
            logger.error(f"Failed to open CMD window: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def open_powershell_window(self,
                                    command: str,
                                    title: str = "Aether AI PowerShell",
                                    stay_open: bool = True) -> Dict[str, Any]:
        """
        Open REAL PowerShell window that stays visible
        
        Args:
            command: PowerShell command to execute
            title: Window title
            stay_open: Keep window open after command finishes
        
        Returns:
            Dict with process info
        """
        try:
            await self._update_progress(f"Opening PowerShell window: {title}", 0.1)
            
            # Build PowerShell command
            if stay_open:
                full_command = f'start powershell -NoExit -Command "Write-Host \'{title}\' -ForegroundColor Cyan; {command}"'
            else:
                full_command = f'start powershell -Command "{command}"'
            
            logger.info(f"Executing: {full_command}")
            
            process = subprocess.Popen(
                full_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            process_id = f"ps_{int(time.time())}"
            self.active_processes[process_id] = process
            
            await self._update_progress(f"PowerShell window opened: {title}", 1.0)
            
            return {
                "success": True,
                "process_id": process_id,
                "pid": process.pid,
                "title": title,
                "command": command
            }
        
        except Exception as e:
            logger.error(f"Failed to open PowerShell window: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def launch_burpsuite(self, 
                              project_file: Optional[str] = None,
                              config_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Launch BurpSuite GUI (Pro or Community)
        
        Args:
            project_file: Path to .burp project file
            config_file: Path to user config file
        
        Returns:
            Dict with launch status
        """
        try:
            await self._update_progress("Launching BurpSuite GUI...", 0.2)
            
            if not self.burpsuite_path:
                await self._update_progress("BurpSuite not found!", 1.0)
                return {
                    "success": False,
                    "error": "BurpSuite not installed or not found in common paths"
                }
            
            # Build command
            cmd = [self.burpsuite_path]
            
            if project_file:
                cmd.extend(["--project-file", project_file])
            
            if config_file:
                cmd.extend(["--config-file", config_file])
            
            logger.info(f"Launching BurpSuite: {' '.join(cmd)}")
            
            await self._update_progress("Starting BurpSuite process...", 0.5)
            
            # Launch BurpSuite
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            process_id = f"burp_{int(time.time())}"
            self.active_processes[process_id] = process
            
            await self._update_progress("BurpSuite GUI launched!", 1.0)
            
            return {
                "success": True,
                "process_id": process_id,
                "pid": process.pid,
                "path": self.burpsuite_path,
                "project_file": project_file
            }
        
        except Exception as e:
            logger.error(f"Failed to launch BurpSuite: {e}")
            await self._update_progress(f"BurpSuite launch failed: {e}", 1.0)
            return {
                "success": False,
                "error": str(e)
            }
    
    async def run_nuclei_scan_live(self,
                                   target: str,
                                   templates: Optional[str] = None,
                                   severity: Optional[str] = None) -> Dict[str, Any]:
        """
        Run Nuclei scan in VISIBLE CMD window with LIVE output
        
        Args:
            target: Target URL or domain
            templates: Template path or tag (-t)
            severity: Severity filter (critical, high, medium, low)
        
        Returns:
            Dict with scan info
        """
        try:
            await self._update_progress(f"Preparing Nuclei scan for {target}", 0.1)
            
            if not self.nuclei_path:
                # Try to find nuclei
                self.nuclei_path = self._find_nuclei()
                
                if not self.nuclei_path:
                    return {
                        "success": False,
                        "error": "Nuclei not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                    }
            
            # Build nuclei command
            cmd_parts = ["nuclei", "-u", target]
            
            if templates:
                cmd_parts.extend(["-t", templates])
            
            if severity:
                cmd_parts.extend(["-severity", severity])
            
            # Add output formatting
            cmd_parts.extend(["-json", "-o", f"nuclei_scan_{int(time.time())}.json"])
            
            command = " ".join(cmd_parts)
            
            await self._update_progress(f"Starting Nuclei scan in live window", 0.3)
            
            # Open CMD window with nuclei scan
            result = await self.open_cmd_window(
                command=command,
                title=f"Nuclei Scan - {target}",
                stay_open=True
            )
            
            if result["success"]:
                await self._update_progress(f"Nuclei scan running live! Check the window", 1.0)
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to run Nuclei scan: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def open_terminal_with_commands(self,
                                         commands: list,
                                         title: str = "Aether AI Terminal") -> Dict[str, Any]:
        """
        Open terminal and execute multiple commands sequentially
        
        Args:
            commands: List of commands to execute
            title: Window title
        
        Returns:
            Dict with execution info
        """
        try:
            # Join commands with && (execute sequentially)
            full_command = " && ".join(commands)
            
            # Add pause at the end to see results
            full_command += " && echo. && echo [DONE] Press any key to close... && pause"
            
            return await self.open_cmd_window(
                command=full_command,
                title=title,
                stay_open=False  # Will stay open due to pause
            )
        
        except Exception as e:
            logger.error(f"Failed to open terminal: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def close_process(self, process_id: str) -> bool:
        """Close a specific process"""
        if process_id in self.active_processes:
            try:
                process = self.active_processes[process_id]
                process.terminate()
                del self.active_processes[process_id]
                return True
            except Exception as e:
                logger.error(f"Failed to close process {process_id}: {e}")
                return False
        return False
    
    def close_all_processes(self):
        """Close all active processes"""
        for process_id in list(self.active_processes.keys()):
            self.close_process(process_id)
    
    async def show_live_dashboard_update(self, 
                                        task_name: str,
                                        status: str,
                                        progress: float,
                                        details: str = "") -> Dict[str, Any]:
        """
        Send real-time update to visual dashboard
        
        Args:
            task_name: Name of the task
            status: Current status (running, completed, failed)
            progress: Progress percentage (0-100)
            details: Additional details to show
        
        Returns:
            Update info
        """
        update = {
            "task_name": task_name,
            "status": status,
            "progress": progress,
            "details": details,
            "timestamp": time.time()
        }
        
        # Call progress callback
        message = f"{task_name}: {details}" if details else task_name
        await self._update_progress(message, progress / 100.0)
        
        return update


# Singleton instance
_visual_executor: Optional[VisualExecutor] = None


async def get_visual_executor(progress_callback: Optional[Callable] = None) -> VisualExecutor:
    """Get or create visual executor singleton"""
    global _visual_executor
    
    if _visual_executor is None:
        _visual_executor = VisualExecutor(progress_callback=progress_callback)
    
    return _visual_executor
