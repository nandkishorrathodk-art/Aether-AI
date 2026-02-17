import asyncio
import subprocess
import psutil
from typing import Optional, List, Dict
from pathlib import Path

from src.control.models import ActionType, ActionResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AppLauncher:
    
    def __init__(self):
        self.app_shortcuts = {
            'notepad': 'notepad.exe',
            'calculator': 'calc.exe',
            'cmd': 'cmd.exe',
            'powershell': 'powershell.exe',
            'explorer': 'explorer.exe',
            'chrome': r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            'firefox': r'C:\Program Files\Mozilla Firefox\firefox.exe',
            'edge': r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
            'vscode': r'C:\Users\{user}\AppData\Local\Programs\Microsoft VS Code\Code.exe',
            'burpsuite': r'C:\Program Files\BurpSuitePro\BurpSuitePro.exe',
        }
        
        self._expand_user_paths()
    
    def _expand_user_paths(self):
        import os
        username = os.environ.get('USERNAME', 'User')
        for app, path in self.app_shortcuts.items():
            self.app_shortcuts[app] = path.replace('{user}', username)
    
    async def launch_app(self, app_name: str, args: Optional[List[str]] = None) -> ActionResult:
        app_name_lower = app_name.lower()
        
        if app_name_lower in self.app_shortcuts:
            app_path = self.app_shortcuts[app_name_lower]
        else:
            app_path = app_name
        
        try:
            if not Path(app_path).exists() and not self._is_system_command(app_path):
                return ActionResult(
                    success=False,
                    action_type=ActionType.APP_LAUNCH,
                    error=f"Application not found: {app_path}"
                )
            
            command = [app_path]
            if args:
                command.extend(args)
            
            process = await asyncio.to_thread(
                subprocess.Popen,
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if self._is_console_app(app_path) else 0
            )
            
            logger.info(f"Launched {app_name} (PID: {process.pid})")
            return ActionResult(
                success=True,
                action_type=ActionType.APP_LAUNCH,
                message=f"Launched {app_name} (PID: {process.pid})",
                executed=True
            )
        except Exception as e:
            logger.error(f"Failed to launch {app_name}: {e}")
            return ActionResult(
                success=False,
                action_type=ActionType.APP_LAUNCH,
                error=str(e)
            )
    
    def _is_system_command(self, app_path: str) -> bool:
        system_commands = ['notepad.exe', 'calc.exe', 'cmd.exe', 'powershell.exe', 'explorer.exe']
        return any(cmd in app_path.lower() for cmd in system_commands)
    
    def _is_console_app(self, app_path: str) -> bool:
        console_apps = ['cmd.exe', 'powershell.exe']
        return any(cmd in app_path.lower() for cmd in console_apps)
    
    async def close_app(self, app_name: str, force: bool = False) -> ActionResult:
        try:
            processes_found = []
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    proc_exe = proc.info.get('exe', '').lower() if proc.info.get('exe') else ''
                    
                    if app_name.lower() in proc_name or app_name.lower() in proc_exe:
                        processes_found.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not processes_found:
                return ActionResult(
                    success=False,
                    action_type=ActionType.APP_CLOSE,
                    error=f"No running process found for: {app_name}"
                )
            
            closed_count = 0
            for proc in processes_found:
                try:
                    if force:
                        await asyncio.to_thread(proc.kill)
                    else:
                        await asyncio.to_thread(proc.terminate)
                    
                    await asyncio.to_thread(proc.wait, timeout=3)
                    closed_count += 1
                    logger.info(f"Closed {proc.info['name']} (PID: {proc.info['pid']})")
                except psutil.TimeoutExpired:
                    if force:
                        await asyncio.to_thread(proc.kill)
                        closed_count += 1
                except Exception as e:
                    logger.warning(f"Failed to close process {proc.info['pid']}: {e}")
            
            return ActionResult(
                success=closed_count > 0,
                action_type=ActionType.APP_CLOSE,
                message=f"Closed {closed_count} process(es) for {app_name}",
                executed=True
            )
        except Exception as e:
            logger.error(f"Failed to close {app_name}: {e}")
            return ActionResult(
                success=False,
                action_type=ActionType.APP_CLOSE,
                error=str(e)
            )
    
    async def is_app_running(self, app_name: str) -> bool:
        try:
            for proc in psutil.process_iter(['name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    proc_exe = proc.info.get('exe', '').lower() if proc.info.get('exe') else ''
                    
                    if app_name.lower() in proc_name or app_name.lower() in proc_exe:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return False
        except Exception as e:
            logger.error(f"Failed to check if {app_name} is running: {e}")
            return False
    
    async def get_running_apps(self) -> List[Dict[str, any]]:
        apps = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                try:
                    apps.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'exe': proc.info.get('exe', ''),
                        'create_time': proc.info.get('create_time', 0)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return apps
        except Exception as e:
            logger.error(f"Failed to get running apps: {e}")
            return []
    
    def add_app_shortcut(self, name: str, path: str):
        self.app_shortcuts[name.lower()] = path
        logger.info(f"Added app shortcut: {name} -> {path}")
    
    def get_app_shortcuts(self) -> Dict[str, str]:
        return self.app_shortcuts.copy()
