"""
Windows Service Manager - Makes Aether AI Always-On

Runs Aether as a persistent Windows service that:
- Starts on boot
- Runs in background
- Auto-restarts on crash
- No CLI needed - pure desktop integration
"""

import sys
import os
import time
import asyncio
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    WINDOWS_SERVICE_AVAILABLE = True
except ImportError:
    WINDOWS_SERVICE_AVAILABLE = False
    print("⚠️ pywin32 not installed. Run: pip install pywin32")

from src.utils.logger import get_logger

logger = get_logger(__name__)


class AetherService(win32serviceutil.ServiceFramework):
    """
    Aether AI Windows Service
    
    Usage:
        Install: python windows_service.py install
        Start:   python windows_service.py start
        Stop:    python windows_service.py stop
        Remove:  python windows_service.py remove
    """
    
    _svc_name_ = "AetherAI"
    _svc_display_name_ = "Aether AI v3.0 - Autonomous Assistant"
    _svc_description_ = "Fully autonomous AI assistant running in background. No CLI needed."
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
    
    def SvcStop(self):
        """Stop the service"""
        logger.info("Aether AI service stopping...")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.running = False
    
    def SvcDoRun(self):
        """Main service loop"""
        logger.info("🚀 Aether AI service starting...")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        # Run the main service
        self.main()
    
    def main(self):
        """Main service logic"""
        try:
            # Import Aether components
            from src.api.main import app
            import uvicorn
            from src.config import settings
            
            logger.info("Starting Aether AI FastAPI server...")
            
            # Run FastAPI in background thread
            import threading
            
            def run_server():
                uvicorn.run(
                    app,
                    host=settings.api_host,
                    port=settings.api_port,
                    log_level="info"
                )
            
            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()
            
            logger.info(f"✅ Aether AI running on {settings.api_host}:{settings.api_port}")
            
            # Keep service alive
            while self.running:
                # Check if stop event is set
                rc = win32event.WaitForSingleObject(self.stop_event, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                
                # Heartbeat
                logger.debug("Aether AI service heartbeat...")
            
            logger.info("Aether AI service stopped gracefully")
            
        except Exception as e:
            logger.error(f"Aether AI service error: {e}", exc_info=True)
            servicemanager.LogErrorMsg(f"Aether AI service failed: {e}")


def install_service():
    """Install Aether as Windows service"""
    if not WINDOWS_SERVICE_AVAILABLE:
        print("❌ pywin32 not available. Install with: pip install pywin32")
        return False
    
    try:
        print("Installing Aether AI as Windows service...")
        win32serviceutil.HandleCommandLine(AetherService)
        print("✅ Aether AI service installed successfully!")
        print("\nUsage:")
        print("  Start:  net start AetherAI")
        print("  Stop:   net stop AetherAI")
        print("  Remove: python windows_service.py remove")
        return True
    except Exception as e:
        print(f"❌ Service installation failed: {e}")
        return False


def create_startup_task():
    """
    Create Windows Task Scheduler entry for startup (alternative to service)
    Simpler than full service, works without admin rights
    """
    try:
        import subprocess
        
        # Get Python executable and main script
        python_exe = sys.executable
        script_path = project_root / "src" / "main.py"
        
        task_name = "AetherAI_Startup"
        
        # Create scheduled task XML
        task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Aether AI v3.0 - Starts automatically on login</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions>
    <Exec>
      <Command>{python_exe}</Command>
      <Arguments>"{script_path}"</Arguments>
      <WorkingDirectory>{project_root}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"""
        
        # Save XML to temp file
        xml_path = project_root / "aether_task.xml"
        with open(xml_path, 'w', encoding='utf-16') as f:
            f.write(task_xml)
        
        # Create task using schtasks
        result = subprocess.run(
            ['schtasks', '/Create', '/TN', task_name, '/XML', str(xml_path), '/F'],
            capture_output=True,
            text=True
        )
        
        # Clean up XML
        xml_path.unlink()
        
        if result.returncode == 0:
            print(f"✅ Aether AI startup task created successfully!")
            print(f"   Aether will now start automatically on login")
            print(f"\nManage task:")
            print(f"  View:   schtasks /Query /TN {task_name}")
            print(f"  Delete: schtasks /Delete /TN {task_name} /F")
            return True
        else:
            print(f"❌ Failed to create startup task: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Startup task creation failed: {e}")
        return False


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Service mode
        if WINDOWS_SERVICE_AVAILABLE:
            win32serviceutil.HandleCommandLine(AetherService)
        else:
            print("❌ Windows service support not available")
            print("Install with: pip install pywin32")
    else:
        # Interactive mode - show options
        print("=" * 60)
        print("  AETHER AI v3.0 - ALWAYS-ON INSTALLATION")
        print("=" * 60)
        print("\nOptions:")
        print("1. Install as Windows Service (requires admin)")
        print("2. Install as Startup Task (no admin needed)")
        print("3. Exit")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == "1":
            install_service()
        elif choice == "2":
            create_startup_task()
        else:
            print("Cancelled.")
