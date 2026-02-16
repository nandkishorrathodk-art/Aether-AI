import sys
import os
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.action.automation import (
    SafeScriptExecutor,
    GUIController,
    ApplicationLauncher,
    SafeFileOperations,
    get_command_registry
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


def print_section(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_script_executor():
    print_section("Testing Script Executor")
    
    executor = SafeScriptExecutor(timeout=10)
    
    print("\n1. Testing echo command:")
    result = executor.execute_command("echo", args=["Hello from Aether!"], shell=True)
    print(f"   Success: {result.success}")
    print(f"   Output: {result.output.strip()}")
    print(f"   Time: {result.execution_time:.3f}s")
    
    print("\n2. Testing Python code execution:")
    code = """
import sys
print(f"Python version: {sys.version}")
print("Aether Automation Engine is running!")
"""
    result = executor.execute_python_code(code)
    print(f"   Success: {result.success}")
    print(f"   Output:\n{result.output}")
    
    print("\n3. Testing dangerous command blocking:")
    result = executor.execute_command("del", args=["/F", "C:\\*"], shell=True)
    print(f"   Success: {result.success}")
    print(f"   Error: {result.error}")
    
    return True


def test_file_operations():
    print_section("Testing File Operations")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        file_ops = SafeFileOperations(base_directory=tmpdir)
        
        print("\n1. Creating a file:")
        file_path = os.path.join(tmpdir, "test_aether.txt")
        content = "Aether AI - Your Personal Assistant\nVersion 1.0"
        result = file_ops.write_file(file_path, content)
        print(f"   Success: {result.success}")
        print(f"   Message: {result.message}")
        
        print("\n2. Reading the file:")
        result = file_ops.read_file(file_path)
        print(f"   Success: {result.success}")
        print(f"   Content:\n   {result.data.replace(chr(10), chr(10) + '   ')}")
        
        print("\n3. Listing directory:")
        result = file_ops.list_directory(tmpdir)
        print(f"   Success: {result.success}")
        print(f"   Files found: {len(result.data)}")
        for item in result.data:
            print(f"     - {item['name']} ({item['size']} bytes)")
        
        print("\n4. Copying file:")
        copy_path = os.path.join(tmpdir, "test_aether_copy.txt")
        result = file_ops.copy_file(file_path, copy_path)
        print(f"   Success: {result.success}")
        print(f"   Message: {result.message}")
        
        print("\n5. Searching for files:")
        result = file_ops.search_files(tmpdir, "*.txt")
        print(f"   Success: {result.success}")
        print(f"   Found {len(result.data)} files:")
        for item in result.data:
            print(f"     - {item['name']}")
        
        print("\n6. Getting file info:")
        result = file_ops.get_file_info(file_path)
        print(f"   Success: {result.success}")
        if result.success:
            print(f"   Size: {result.data['size']} bytes")
            print(f"   MD5: {result.data['md5']}")
        
        print("\n7. Testing dangerous path blocking:")
        result = file_ops.read_file("C:\\Windows\\System32\\config\\SAM")
        print(f"   Success: {result.success}")
        print(f"   Error: {result.error}")
    
    return True


def test_application_launcher():
    print_section("Testing Application Launcher")
    
    launcher = ApplicationLauncher()
    
    print("\n1. Launching Notepad:")
    process = launcher.launch_application('notepad')
    if process:
        print(f"   Success! PID: {process.pid}")
        
        print("\n2. Waiting 2 seconds...")
        time.sleep(2)
        
        print("\n3. Closing Notepad:")
        success = launcher.close_application(process.pid, force=True)
        print(f"   Closed: {success}")
    else:
        print("   Failed to launch Notepad")
    
    return True


def test_gui_controller():
    print_section("Testing GUI Controller")
    
    controller = GUIController(pause_duration=0.2)
    
    print("\n1. Getting screen size:")
    size = controller.get_screen_size()
    print(f"   Screen size: {size[0]}x{size[1]}")
    
    print("\n2. Getting mouse position:")
    pos = controller.get_mouse_position()
    print(f"   Mouse position: ({pos[0]}, {pos[1]})")
    
    print("\n3. Taking screenshot:")
    screenshot = controller.screenshot()
    if screenshot:
        print(f"   Screenshot captured: {screenshot.size}")
    else:
        print("   Failed to capture screenshot")
    
    return True


def test_command_registry():
    print_section("Testing Command Registry")
    
    registry = get_command_registry()
    
    print("\n1. Listing all commands:")
    result = registry.execute_command("help")
    print(f"   Success: {result.success}")
    print(f"   Total commands: {len(result.data)}")
    print("\n   Available commands:")
    for cmd in result.data[:10]:
        print(f"     - {cmd['name']}: {cmd['description']}")
    if len(result.data) > 10:
        print(f"     ... and {len(result.data) - 10} more")
    
    print("\n2. Getting current time:")
    result = registry.execute_command("time")
    print(f"   Success: {result.success}")
    print(f"   Time: {result.data['time']}")
    print(f"   Execution time: {result.execution_time:.3f}s")
    
    print("\n3. Getting current date:")
    result = registry.execute_command("date")
    print(f"   Success: {result.success}")
    print(f"   Date: {result.data['date']}")
    
    print("\n4. Getting system information:")
    result = registry.execute_command("system_info")
    print(f"   Success: {result.success}")
    if result.success:
        print(f"   Platform: {result.data['platform']}")
        print(f"   Architecture: {result.data['architecture']}")
        print(f"   CPU Count: {result.data['cpu_count']}")
        print(f"   Total Memory: {result.data['total_memory'] / (1024**3):.2f} GB")
    
    print("\n5. Getting CPU usage:")
    result = registry.execute_command("cpu_usage", interval=0.5)
    print(f"   Success: {result.success}")
    print(f"   CPU Usage: {result.data['cpu_usage']}%")
    
    print("\n6. Getting memory usage:")
    result = registry.execute_command("memory_usage")
    print(f"   Success: {result.success}")
    if result.success:
        total_gb = result.data['total'] / (1024**3)
        used_gb = result.data['used'] / (1024**3)
        print(f"   Used: {used_gb:.2f} GB / {total_gb:.2f} GB ({result.data['percent']}%)")
    
    print("\n7. Getting disk usage:")
    result = registry.execute_command("disk_usage", path="C:\\" if sys.platform == 'win32' else "/")
    print(f"   Success: {result.success}")
    if result.success:
        total_gb = result.data['total'] / (1024**3)
        free_gb = result.data['free'] / (1024**3)
        print(f"   Free: {free_gb:.2f} GB / {total_gb:.2f} GB ({result.data['percent']}% used)")
    
    print("\n8. Creating a custom command:")
    def greet(**kwargs):
        from src.action.automation import CommandResult
        name = kwargs.get('name', 'User')
        return CommandResult(
            success=True,
            message=f"Hello, {name}! Welcome to Aether AI!"
        )
    
    registry.register_command("greet", greet, "Greet the user")
    result = registry.execute_command("greet", name="Tony Stark")
    print(f"   Success: {result.success}")
    print(f"   Message: {result.message}")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        registry.file_ops.base_directory = Path(tmpdir)
        
        print("\n9. Testing file commands:")
        file_path = os.path.join(tmpdir, "aether_test.txt")
        
        create_result = registry.execute_command(
            "create_file",
            file_path=file_path,
            content="This is a test file created by Aether AI."
        )
        print(f"   Create file - Success: {create_result.success}")
        
        read_result = registry.execute_command("read_file", file_path=file_path)
        print(f"   Read file - Success: {read_result.success}")
        print(f"   Content: {read_result.data}")
        
        list_result = registry.execute_command("list_files", directory=tmpdir)
        print(f"   List files - Success: {list_result.success}")
        print(f"   Files found: {len(list_result.data)}")
    
    return True


def test_full_workflow():
    print_section("Testing Full Automation Workflow")
    
    registry = get_command_registry()
    
    print("\nSimulating a user request: 'Aether, create a report and tell me the system status'")
    
    print("\nStep 1: Get system information")
    sys_info = registry.execute_command("system_info")
    cpu_usage = registry.execute_command("cpu_usage", interval=0.5)
    mem_usage = registry.execute_command("memory_usage")
    
    print(f"   System: {sys_info.data['platform']}")
    print(f"   CPU Usage: {cpu_usage.data['cpu_usage']}%")
    print(f"   Memory: {mem_usage.data['percent']}% used")
    
    print("\nStep 2: Create a report file")
    with tempfile.TemporaryDirectory() as tmpdir:
        registry.file_ops.base_directory = Path(tmpdir)
        
        report_content = f"""
AETHER AI - SYSTEM STATUS REPORT
{'=' * 50}
Generated: {registry.execute_command('date').data['date']} {registry.execute_command('time').data['time']}

SYSTEM INFORMATION:
- Platform: {sys_info.data['platform']} {sys_info.data['platform_release']}
- Architecture: {sys_info.data['architecture']}
- CPU Count: {sys_info.data['cpu_count']}
- Total Memory: {sys_info.data['total_memory'] / (1024**3):.2f} GB

CURRENT STATUS:
- CPU Usage: {cpu_usage.data['cpu_usage']}%
- Memory Usage: {mem_usage.data['percent']}%
- Available Memory: {mem_usage.data['available'] / (1024**3):.2f} GB

Report generated by Aether AI Automation Engine
"""
        
        report_path = os.path.join(tmpdir, "system_report.txt")
        create_result = registry.execute_command(
            "create_file",
            file_path=report_path,
            content=report_content
        )
        
        print(f"   Report created: {create_result.success}")
        
        print("\nStep 3: Read the report back")
        read_result = registry.execute_command("read_file", file_path=report_path)
        if read_result.success:
            print("\n   REPORT CONTENT:")
            print("   " + read_result.data.replace("\n", "\n   "))
    
    print("\nWorkflow completed successfully!")
    
    return True


def main():
    print("\n" + "=" * 70)
    print("  AETHER AI - AUTOMATION ENGINE TEST SUITE")
    print("=" * 70)
    
    tests = [
        ("Script Executor", test_script_executor),
        ("File Operations", test_file_operations),
        ("Application Launcher", test_application_launcher),
        ("GUI Controller", test_gui_controller),
        ("Command Registry", test_command_registry),
        ("Full Workflow", test_full_workflow)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            print(f"\n\nRunning: {test_name}")
            success = test_func()
            results.append((test_name, success, None))
        except Exception as e:
            logger.error(f"Test failed: {test_name}", exc_info=True)
            results.append((test_name, False, str(e)))
    
    print("\n\n" + "=" * 70)
    print("  TEST RESULTS SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    for test_name, success, error in results:
        status = "[PASS]" if success else "[FAIL]"
        print(f"{status}  {test_name}")
        if error:
            print(f"        Error: {error}")
    
    print("\n" + "=" * 70)
    print(f"  TOTAL: {passed}/{total} tests passed ({passed*100//total}%)")
    print("=" * 70)
    
    if passed == total:
        print("\nAll tests passed! Automation Engine is ready!")
    else:
        print(f"\n{total - passed} test(s) failed. Please review the errors above.")


if __name__ == "__main__":
    main()
