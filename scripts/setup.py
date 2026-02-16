import os
import sys
from pathlib import Path

def check_python_version():
    if sys.version_info < (3, 10):
        print("❌ Python 3.10+ required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✓ Python {sys.version.split()[0]}")
    return True

def check_virtual_env():
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✓ Virtual environment active")
        return True
    else:
        print("⚠ Not in virtual environment")
        print("   Run: python -m venv venv")
        print("   Then: venv\\Scripts\\activate (Windows) or source venv/bin/activate (Linux)")
        return False

def check_dependencies():
    try:
        import fastapi
        import openai
        import anthropic
        import google.generativeai
        import groq
        print("✓ Core dependencies installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        print("   Run: pip install -r requirements.txt")
        return False

def check_env_file():
    env_path = Path(".env")
    if env_path.exists():
        print("✓ .env file exists")
        
        with open(env_path) as f:
            content = f.read()
            
        has_key = False
        providers = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", 
                     "GROQ_API_KEY", "FIREWORKS_API_KEY", "OPENROUTER_API_KEY"]
        
        configured = []
        for provider in providers:
            if provider in content:
                value = content.split(provider)[1].split('\n')[0].strip('=').strip()
                if value and value != "":
                    has_key = True
                    configured.append(provider.replace("_API_KEY", ""))
        
        if has_key:
            print(f"✓ API keys configured: {', '.join(configured)}")
            return True
        else:
            print("⚠ No API keys configured")
            print("   Edit .env and add at least one API key")
            return False
    else:
        print("❌ .env file not found")
        print("   Run: copy .env.example .env (Windows) or cp .env.example .env (Linux)")
        return False

def create_directories():
    dirs = ["data", "logs", "models"]
    for dir_name in dirs:
        Path(dir_name).mkdir(exist_ok=True)
    print(f"✓ Directories created: {', '.join(dirs)}")

def main():
    print("=" * 60)
    print("Aether AI - Setup Verification")
    print("=" * 60)
    print()
    
    checks = [
        check_python_version(),
        check_virtual_env(),
        check_dependencies(),
        check_env_file(),
    ]
    
    print()
    create_directories()
    
    print()
    print("=" * 60)
    
    if all(checks):
        print("✓ All checks passed! Ready to start.")
        print()
        print("Next steps:")
        print("  1. Start API: uvicorn src.api.main:app --reload")
        print("  2. Test providers: python scripts/test_providers.py")
        print("  3. View docs: http://localhost:8000/docs")
    else:
        print("⚠ Some checks failed. Please fix the issues above.")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
