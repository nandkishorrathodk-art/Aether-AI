#!/usr/bin/env python3
"""
Aether AI Installation Verification Script
Checks all components and dependencies are properly installed
"""

import sys
import os
import subprocess
import importlib
from pathlib import Path
from typing import Tuple, List

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(60)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.RESET}\n")

def print_check(name: str, passed: bool, details: str = ""):
    """Print check result"""
    status = f"{Colors.GREEN}✓ PASS{Colors.RESET}" if passed else f"{Colors.RED}✗ FAIL{Colors.RESET}"
    print(f"{status} - {name}")
    if details:
        print(f"      {details}")

def check_python_version() -> Tuple[bool, str]:
    """Check Python version >= 3.8"""
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    
    if version.major >= 3 and version.minor >= 8:
        return True, f"Python {version_str}"
    else:
        return False, f"Python {version_str} (requires 3.8+)"

def check_python_package(package: str, import_name: str = None) -> Tuple[bool, str]:
    """Check if Python package is installed"""
    if import_name is None:
        import_name = package
    
    try:
        mod = importlib.import_module(import_name)
        version = getattr(mod, '__version__', 'unknown')
        return True, f"{package} {version}"
    except ImportError:
        return False, f"{package} not installed"

def check_node() -> Tuple[bool, str]:
    """Check Node.js installation"""
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, f"Node.js {result.stdout.strip()}"
        else:
            return False, "Node.js not found"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, "Node.js not found in PATH"

def check_npm() -> Tuple[bool, str]:
    """Check npm installation"""
    try:
        result = subprocess.run(['npm', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, f"npm {result.stdout.strip()}"
        else:
            return False, "npm not found"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, "npm not found in PATH"

def check_directory(path: str, required: bool = True) -> Tuple[bool, str]:
    """Check if directory exists"""
    exists = Path(path).exists()
    
    if exists:
        return True, f"{path} exists"
    else:
        if required:
            return False, f"{path} not found (required)"
        else:
            return True, f"{path} not found (optional)"

def check_file(path: str, required: bool = True) -> Tuple[bool, str]:
    """Check if file exists"""
    exists = Path(path).exists()
    
    if exists:
        size = Path(path).stat().st_size
        size_str = f"{size / 1024:.1f} KB" if size < 1024*1024 else f"{size / 1024 / 1024:.1f} MB"
        return True, f"{path} ({size_str})"
    else:
        if required:
            return False, f"{path} not found (required)"
        else:
            return True, f"{path} not found (optional)"

def check_env_file() -> Tuple[bool, str]:
    """Check .env file and API keys"""
    if not Path('.env').exists():
        return False, ".env file not found. Copy .env.example to .env"
    
    # Check for at least one API key
    with open('.env', 'r') as f:
        content = f.read()
        
    api_keys = [
        'OPENAI_API_KEY',
        'ANTHROPIC_API_KEY',
        'GOOGLE_API_KEY',
        'GROQ_API_KEY',
        'FIREWORKS_API_KEY',
        'OPENROUTER_API_KEY'
    ]
    
    configured_keys = []
    for key in api_keys:
        if f"{key}=" in content and not f"{key}=your-" in content and not f"{key}=sk-" in content:
            # Check if value is not empty and not placeholder
            lines = content.split('\n')
            for line in lines:
                if line.startswith(f"{key}=") and len(line.split('=', 1)[1].strip()) > 10:
                    configured_keys.append(key.replace('_API_KEY', ''))
                    break
    
    if configured_keys:
        return True, f"API keys configured: {', '.join(configured_keys)}"
    else:
        return False, "No API keys configured. Add at least one to .env"

def check_npm_packages() -> Tuple[bool, str]:
    """Check if npm packages are installed"""
    node_modules = Path('ui/node_modules')
    
    if not node_modules.exists():
        return False, "node_modules not found. Run: cd ui && npm install"
    
    # Count packages
    try:
        package_count = len(list(node_modules.iterdir()))
        return True, f"{package_count} npm packages installed"
    except:
        return False, "Could not verify npm packages"

def run_all_checks() -> bool:
    """Run all verification checks"""
    print_header("AETHER AI INSTALLATION VERIFICATION")
    
    all_passed = True
    
    # System checks
    print(f"{Colors.BOLD}System Requirements:{Colors.RESET}")
    checks: List[Tuple[str, Tuple[bool, str]]] = [
        ("Python Version", check_python_version()),
        ("Node.js", check_node()),
        ("npm", check_npm()),
    ]
    
    for name, (passed, details) in checks:
        print_check(name, passed, details)
        all_passed = all_passed and passed
    
    # Python packages
    print(f"\n{Colors.BOLD}Python Dependencies:{Colors.RESET}")
    packages = [
        ('fastapi', 'fastapi'),
        ('uvicorn', 'uvicorn'),
        ('chromadb', 'chromadb'),
        ('PyTorch', 'torch'),
        ('Transformers', 'transformers'),
        ('OpenAI SDK', 'openai'),
        ('Anthropic SDK', 'anthropic'),
        ('Google AI SDK', 'google.generativeai'),
        ('Groq SDK', 'groq'),
        ('PyAutoGUI', 'pyautogui'),
        ('PyAudio', 'pyaudio'),
        ('pyttsx3', 'pyttsx3'),
        ('SQLAlchemy', 'sqlalchemy'),
        ('pytest', 'pytest'),
    ]
    
    for name, import_name in packages:
        passed, details = check_python_package(name, import_name)
        print_check(name, passed, details)
        # Don't fail on optional packages
        if name not in ['PyAudio', 'pytest']:
            all_passed = all_passed and passed
    
    # Project structure
    print(f"\n{Colors.BOLD}Project Structure:{Colors.RESET}")
    directories = [
        ('src/', True),
        ('ui/', True),
        ('scripts/', True),
        ('tests/', True),
        ('data/', False),
        ('logs/', False),
        ('models/', False),
    ]
    
    for path, required in directories:
        passed, details = check_directory(path, required)
        print_check(path, passed, details)
        if required:
            all_passed = all_passed and passed
    
    # Important files
    print(f"\n{Colors.BOLD}Important Files:{Colors.RESET}")
    files = [
        ('README.md', True),
        ('requirements.txt', True),
        ('ui/package.json', True),
        ('src/main.py', True),
        ('ui/main.js', True),
        ('.env', True),
        ('install.bat', True),
        ('start-aether.bat', True),
    ]
    
    for path, required in files:
        passed, details = check_file(path, required)
        print_check(path, passed, details)
        if required:
            all_passed = all_passed and passed
    
    # Configuration
    print(f"\n{Colors.BOLD}Configuration:{Colors.RESET}")
    passed, details = check_env_file()
    print_check(".env Configuration", passed, details)
    all_passed = all_passed and passed
    
    # Node.js packages
    print(f"\n{Colors.BOLD}Frontend Dependencies:{Colors.RESET}")
    passed, details = check_npm_packages()
    print_check("npm Packages", passed, details)
    all_passed = all_passed and passed
    
    # Final result
    print_header("VERIFICATION RESULT")
    
    if all_passed:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ All checks passed!{Colors.RESET}")
        print(f"\n{Colors.GREEN}Aether AI is ready to use.{Colors.RESET}")
        print(f"\nNext steps:")
        print(f"  1. Review .env configuration: notepad .env")
        print(f"  2. Start Aether AI: start-aether.bat")
        print(f"  3. Read the docs: README.md, QUICKSTART.md")
        return True
    else:
        print(f"{Colors.RED}{Colors.BOLD}✗ Some checks failed{Colors.RESET}")
        print(f"\n{Colors.RED}Please fix the issues above and run this script again.{Colors.RESET}")
        print(f"\nFor help:")
        print(f"  - Run: install.bat")
        print(f"  - Read: README.md")
        print(f"  - Check: docs/DEPLOYMENT.md")
        return False

if __name__ == "__main__":
    try:
        # Change to project root
        script_dir = Path(__file__).parent
        project_root = script_dir.parent
        os.chdir(project_root)
        
        success = run_all_checks()
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Verification cancelled by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Error during verification: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
