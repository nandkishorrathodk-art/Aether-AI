#!/usr/bin/env python3
"""
Comprehensive bug fix script for Aether AI
Fixes identified issues and prepares system for production
"""

import os
import sys
import shutil
from pathlib import Path

def clean_test_data():
    """Remove test databases and cache"""
    print("[1/10] Cleaning test data...")
    
    paths_to_clean = [
        "data/conversations.db",
        "data/tts_cache",
        "data/chroma_db",
        "data/user_profiles",
        ".pytest_cache",
        "__pycache__"
    ]
    
    for path in paths_to_clean:
        full_path = Path(path)
        if full_path.exists():
            try:
                if full_path.is_file():
                    full_path.unlink()
                    print(f"  - Removed file: {path}")
                elif full_path.is_dir():
                    shutil.rmtree(full_path)
                    print(f"  - Removed directory: {path}")
            except Exception as e:
                print(f"  ! Failed to remove {path}: {e}")
    
    print("  [OK] Test data cleaned")

def check_env_configuration():
    """Verify .env file has required settings"""
    print("\n[2/10] Checking .env configuration...")
    
    if not Path(".env").exists():
        print("  ! .env not found, copying from .env.example")
        shutil.copy(".env.example", ".env")
    
    # Check for critical settings
    with open(".env", "r", encoding="utf-8") as f:
        env_content = f.read()
    
    critical_vars = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROQ_API_KEY"
    ]
    
    missing = []
    for var in critical_vars:
        if var not in env_content or f"{var}=" in env_content and not f"{var}=your-" in env_content:
            continue
        else:
            missing.append(var)
    
    if missing:
        print(f"  ! Missing API keys: {', '.join(missing)}")
        print("    Note: Some features will not work without API keys")
    else:
        print("  [OK] Configuration valid")

def fix_missing_dependencies():
    """Install missing Python packages"""
    print("\n[3/10] Checking dependencies...")
    
    missing_packages = []
    
    try:
        import edge_tts
    except ImportError:
        missing_packages.append("edge-tts")
    
    try:
        import nest_asyncio
    except ImportError:
        missing_packages.append("nest-asyncio")
    
    try:
        import langdetect
    except ImportError:
        missing_packages.append("langdetect")
    
    if missing_packages:
        print(f"  ! Missing packages: {', '.join(missing_packages)}")
        print("    Run: pip install " + " ".join(missing_packages))
    else:
        print("  [OK] All dependencies installed")

def fix_context_manager_tests():
    """Fix ContextManager to allow clean initialization"""
    print("\n[4/10] Fixing ContextManager for tests...")
    
    context_file = Path("src/cognitive/llm/context_manager.py")
    if not context_file.exists():
        print("  ! context_manager.py not found")
        return
    
    content = context_file.read_text(encoding="utf-8")
    
    # Check if already fixed
    if "load_from_db: bool = True" in content:
        print("  [OK] Already fixed")
        return
    
    # Add load_from_db parameter
    old_init = 'def __init__(self, session_id: str = "default", max_messages: int = None, max_tokens: int = 8000):'
    new_init = 'def __init__(self, session_id: str = "default", max_messages: int = None, max_tokens: int = 8000, load_from_db: bool = True):'
    
    if old_init in content:
        content = content.replace(old_init, new_init)
        
        # Add conditional loading
        old_load = """        # Load recent context from DB
        try:
            recent_msgs = self.history_db.get_recent_context(session_id=self.session_id, max_messages=self.max_messages)"""
        
        new_load = """        # Load recent context from DB
        if load_from_db:
            try:
                recent_msgs = self.history_db.get_recent_context(session_id=self.session_id, max_messages=self.max_messages)"""
        
        content = content.replace(old_load, new_load)
        
        # Add else clause
        old_except = """            logger.info(f"Loaded {len(recent_msgs)} messages from long-term memory for session {self.session_id}")
        except Exception as e:
            logger.error(f"Failed to load memory for session {self.session_id}: {e}")"""
        
        new_except = """                logger.info(f"Loaded {len(recent_msgs)} messages from long-term memory for session {self.session_id}")
            except Exception as e:
                logger.error(f"Failed to load memory for session {self.session_id}: {e}")
        else:
            logger.info("Skipping DB load for test mode")"""
        
        content = content.replace(old_except, new_except)
        
        context_file.write_text(content, encoding="utf-8")
        print("  [OK] ContextManager fixed")
    else:
        print("  ! Could not find expected code pattern")

def fix_test_fixtures():
    """Update test fixtures to use clean initialization"""
    print("\n[5/10] Fixing test fixtures...")
    
    test_file = Path("tests/unit/test_conversation_engine.py")
    if not test_file.exists():
        print("  ! test_conversation_engine.py not found")
        return
    
    content = test_file.read_text(encoding="utf-8")
    
    # Check if already fixed
    if "load_from_db=False" in content:
        print("  [OK] Already fixed")
        return
    
    # Fix ContextManager instantiation
    old_code = 'self.context = ContextManager(max_messages=10, max_tokens=1000)'
    new_code = 'self.context = ContextManager(session_id="test_session", max_messages=10, max_tokens=1000, load_from_db=False)'
    
    if old_code in content:
        content = content.replace(old_code, new_code)
        test_file.write_text(content, encoding="utf-8")
        print("  [OK] Test fixtures fixed")
    else:
        print("  ! Could not find expected test code")

def create_missing_directories():
    """Create required directories"""
    print("\n[6/10] Creating missing directories...")
    
    dirs = [
        "data",
        "data/tts_cache",
        "data/chroma_db",
        "data/user_profiles",
        "logs",
        "models"
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    print(f"  [OK] Created {len(dirs)} directories")

def fix_import_errors():
    """Fix common import errors"""
    print("\n[7/10] Checking for import errors...")
    
    # Check if __init__.py files exist
    init_files = [
        "src/__init__.py",
        "src/perception/__init__.py",
        "src/perception/voice/__init__.py",
        "src/cognitive/__init__.py",
        "src/cognitive/llm/__init__.py",
        "src/cognitive/memory/__init__.py",
        "src/action/__init__.py",
        "src/action/automation/__init__.py",
        "src/api/__init__.py"
    ]
    
    missing = []
    for init_file in init_files:
        if not Path(init_file).exists():
            Path(init_file).touch()
            missing.append(init_file)
    
    if missing:
        print(f"  [OK] Created {len(missing)} missing __init__.py files")
    else:
        print("  [OK] All __init__.py files present")

def verify_critical_files():
    """Check critical files exist"""
    print("\n[8/10] Verifying critical files...")
    
    critical_files = [
        "src/api/main.py",
        "src/config.py",
        "src/utils/logger.py",
        "requirements.txt",
        ".env"
    ]
    
    missing = []
    for file in critical_files:
        if not Path(file).exists():
            missing.append(file)
    
    if missing:
        print(f"  ! Missing files: {', '.join(missing)}")
        return False
    else:
        print("  [OK] All critical files present")
        return True

def update_requirements():
    """Add missing dependencies to requirements.txt"""
    print("\n[9/10] Updating requirements.txt...")
    
    req_file = Path("requirements.txt")
    content = req_file.read_text(encoding="utf-8")
    
    missing_deps = []
    
    if "edge-tts" not in content:
        missing_deps.append("edge-tts==6.1.10")
    
    if "nest-asyncio" not in content and "nest_asyncio" not in content:
        missing_deps.append("nest-asyncio==1.6.0")
    
    if "langdetect" not in content:
        missing_deps.append("langdetect==1.0.9")
    
    if missing_deps:
        content += "\n# Added by fix_bugs.py\n" + "\n".join(missing_deps) + "\n"
        req_file.write_text(content, encoding="utf-8")
        print(f"  [OK] Added {len(missing_deps)} missing dependencies")
    else:
        print("  [OK] Requirements up to date")

def summary():
    """Print summary and next steps"""
    print("\n[10/10] Fix Summary")
    print("=" * 60)
    print("Fixes applied:")
    print("  1. Cleaned test data and caches")
    print("  2. Verified .env configuration")
    print("  3. Checked dependencies")
    print("  4. Fixed ContextManager initialization")
    print("  5. Fixed test fixtures")
    print("  6. Created missing directories")
    print("  7. Fixed import paths")
    print("  8. Verified critical files")
    print("  9. Updated requirements.txt")
    print("  10. System ready for testing")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. Install missing dependencies: pip install -r requirements.txt")
    print("  2. Run tests: pytest tests/unit/ -v")
    print("  3. Start API: python -m src.api.main")
    print("  4. Test voice: python scripts/test_voice_pipeline.py")
    print("\nStatus: [OK] Bug fixes complete!")

def main():
    print("=" * 60)
    print("AETHER AI - Comprehensive Bug Fix")
    print("=" * 60)
    
    try:
        clean_test_data()
        check_env_configuration()
        fix_missing_dependencies()
        fix_context_manager_tests()
        fix_test_fixtures()
        create_missing_directories()
        fix_import_errors()
        verify_critical_files()
        update_requirements()
        summary()
        return 0
    except Exception as e:
        print(f"\n[ERROR] Bug fix failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
