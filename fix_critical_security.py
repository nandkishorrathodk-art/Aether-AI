"""
Auto-Fix Critical Security Vulnerabilities in Aether AI
Fixes CVE-1, CVE-2, CVE-3 from Bug Bounty Report
"""

import os
import re
from pathlib import Path

def fix_command_injection():
    """Fix CVE-1: Remove shell=True from subprocess calls"""
    files_to_fix = [
        "src/action/tasks/burpsuite_tasks.py",
        "src/action/security/burpsuite.py",
        "src/features/automation.py"
    ]
    
    fixed_count = 0
    for file_path in files_to_fix:
        if not os.path.exists(file_path):
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace shell=True with shell=False
        if 'shell=True' in content:
            new_content = content.replace('shell=True', 'shell=False')
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            print(f"[OK] Fixed: {file_path} - Removed shell=True")
            fixed_count += 1
    
    return fixed_count

def fix_auth_bypass():
    """Fix CVE-2: Remove development mode auth bypass"""
    file_path = "src/api/middleware/auth.py"
    
    if not os.path.exists(file_path):
        print(f"[WARN] File not found: {file_path}")
        return 0
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace auth bypass with secure version
    old_code = '''    # Allow unauthenticated access in development mode
    if os.getenv("AETHER_ENV") == "development":
        return "dev-user"
    '''
    
    new_code = '''    # REMOVED: Development mode bypass (SECURITY FIX CVE-2)
    # Authentication is now REQUIRED in all environments
    '''
    
    if old_code in content:
        new_content = content.replace(old_code, new_code)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"[OK] Fixed: {file_path} - Removed auth bypass")
        return 1
    else:
        print(f"[INFO] {file_path} - Auth bypass already fixed or not found")
        return 0

def fix_hardcoded_key():
    """Fix CVE-3: Remove hardcoded default API key"""
    file_path = "src/api/middleware/auth.py"
    
    if not os.path.exists(file_path):
        print(f"[WARN] File not found: {file_path}")
        return 0
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace hardcoded key with secure version
    old_code = '''VALID_API_KEYS = {
    os.getenv("AETHER_API_KEY", "aether-dev-key-12345")
}'''
    
    new_code = '''# SECURITY FIX CVE-3: No default API key
api_key = os.getenv("AETHER_API_KEY")
if not api_key:
    raise ValueError("AETHER_API_KEY environment variable must be set!")
VALID_API_KEYS = {api_key}'''
    
    if old_code in content:
        new_content = content.replace(old_code, new_code)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"[OK] Fixed: {file_path} - Removed hardcoded API key")
        return 1
    else:
        print(f"[INFO] {file_path} - Hardcoded key already fixed or not found")
        return 0

def fix_weak_password():
    """Fix CVE-6: Remove weak default master password"""
    files_to_fix = [
        "src/security/encryption.py",
        "src/security/crypto.py"
    ]
    
    fixed_count = 0
    for file_path in files_to_fix:
        if not os.path.exists(file_path):
            continue
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace weak password default
        old_pattern = r'os\.getenv\("AETHER_MASTER_PASSWORD",\s*"changeme"\)'
        new_code = '''os.getenv("AETHER_MASTER_PASSWORD") or (() if True else (_ for _ in ()).throw(ValueError("AETHER_MASTER_PASSWORD must be set!")))()'''
        
        if re.search(old_pattern, content):
            new_content = re.sub(
                old_pattern,
                'os.getenv("AETHER_MASTER_PASSWORD") or _raise_password_error()',
                content
            )
            
            # Add helper function at top of file
            if '_raise_password_error' not in new_content:
                import_section = new_content.split('\n\n')[0]
                new_content = new_content.replace(
                    import_section,
                    import_section + '\n\ndef _raise_password_error():\n    raise ValueError("AETHER_MASTER_PASSWORD environment variable must be set and be 16+ characters!")\n'
                )
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            print(f"[OK] Fixed: {file_path} - Removed weak password default")
            fixed_count += 1
    
    return fixed_count

def create_secure_env_template():
    """Create .env.secure template with secure defaults"""
    template = """# Aether AI - Secure Configuration Template
# COPY THIS TO .env AND FILL IN YOUR VALUES

# REQUIRED: Strong API key (32+ characters recommended)
AETHER_API_KEY=CHANGE_ME_TO_RANDOM_STRING_32_CHARS_OR_MORE

# REQUIRED: Strong master password (16+ characters)
AETHER_MASTER_PASSWORD=CHANGE_ME_TO_STRONG_PASSWORD_16_CHARS_MIN

# Environment (use 'production' for deployed instances)
AETHER_ENV=production

# AI Provider Keys
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GROQ_API_KEY=
OPENROUTER_API_KEY=

# CORS - Restrict to your domain in production
ALLOWED_ORIGINS=https://yourdomain.com

# DO NOT USE THESE IN PRODUCTION:
# ❌ AETHER_ENV=development
# ❌ AETHER_API_KEY=aether-dev-key-12345
# ❌ AETHER_MASTER_PASSWORD=changeme
"""
    
    with open('.env.secure', 'w', encoding='utf-8') as f:
        f.write(template)
    
    print("[OK] Created: .env.secure template")
    return 1

def main():
    print("=" * 60)
    print("[SECURITY] Aether AI - Critical Security Fixes")
    print("=" * 60)
    print()
    
    fixes_applied = 0
    
    print("[FIX] CVE-1: Command Injection (shell=True)...")
    fixes_applied += fix_command_injection()
    print()
    
    print("[FIX] CVE-2: Authentication Bypass...")
    fixes_applied += fix_auth_bypass()
    print()
    
    print("[FIX] CVE-3: Hardcoded API Key...")
    fixes_applied += fix_hardcoded_key()
    print()
    
    print("[FIX] CVE-6: Weak Master Password...")
    fixes_applied += fix_weak_password()
    print()
    
    print("[CREATE] Secure .env template...")
    fixes_applied += create_secure_env_template()
    print()
    
    print("=" * 60)
    print(f"[SUCCESS] Security Fixes Applied: {fixes_applied}")
    print("=" * 60)
    print()
    print("[WARNING] IMPORTANT: Next Steps")
    print("1. Review changes in affected files")
    print("2. Copy .env.secure to .env and fill in strong values")
    print("3. Test authentication with new API key")
    print("4. Restart Aether AI")
    print("5. Review full report: BUG_BOUNTY_REPORT_2026-02-16.md")
    print()

if __name__ == "__main__":
    main()
