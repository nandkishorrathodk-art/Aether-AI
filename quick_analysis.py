#!/usr/bin/env python3
"""Quick analysis - focus on large directories only"""

import os
from pathlib import Path

def get_dir_size(path):
    """Get directory size in MB"""
    total = 0
    try:
        for entry in os.scandir(path):
            if entry.is_file():
                total += entry.stat().st_size
            elif entry.is_dir():
                total += get_dir_size(entry.path)
    except:
        pass
    return total

def count_files(path):
    """Count files in directory"""
    count = 0
    try:
        for entry in os.scandir(path):
            if entry.is_file():
                count += 1
            elif entry.is_dir():
                count += count_files(entry.path)
    except:
        pass
    return count

print("=" * 70)
print("AETHER AI - QUICK MERGE ANALYSIS")
print("=" * 70)

# Check major directories
dirs_to_check = {
    'venv': 'Python virtual environment (CAN RECREATE)',
    'ui/node_modules': 'Electron UI dependencies (CAN REINSTALL)',
    'src-ts/node_modules': 'TypeScript backend deps (CAN REINSTALL)',
    'aether-rust/target': 'Rust build artifacts (CAN REBUILD)',
    '.git': 'Git repository (KEEP for version control)',
    'htmlcov': 'Test coverage reports (CAN REMOVE)',
    '.pytest_cache': 'Pytest cache (CAN REMOVE)',
    'data': 'User data and databases (KEEP)',
    'models': 'AI models (KEEP)',
    'src': 'Core Python source code (KEEP)',
    'ui/src': 'UI source code (KEEP)',
    'docs': 'Documentation (KEEP)'
}

print("\nDirectory Analysis:")
print("-" * 70)

total_removable = 0
total_keep = 0

for dir_path, description in dirs_to_check.items():
    if os.path.exists(dir_path):
        size_mb = get_dir_size(dir_path) / (1024**2)
        file_count = count_files(dir_path)
        
        status = "✓" if "KEEP" in description else "×"
        print(f"{status} {dir_path:30} {size_mb:8.0f} MB | {file_count:6} files")
        print(f"   → {description}")
        
        if "CAN" in description:
            total_removable += size_mb
        else:
            total_keep += size_mb
    else:
        print(f"  {dir_path:30} NOT FOUND")

print("\n" + "=" * 70)
print("MERGE OPTIONS")
print("=" * 70)

print(f"\n1. FULL PROJECT (as-is)")
print(f"   - Size: {(total_removable + total_keep):.0f} MB")
print(f"   - Includes all dependencies")
print(f"   - Ready to run immediately")

print(f"\n2. CLEAN PROJECT (recommended)")
print(f"   - Size: {total_keep:.0f} MB")
print(f"   - Core source code only")
print(f"   - Dependencies can be reinstalled")
print(f"   - Savings: {total_removable:.0f} MB")

print(f"\n3. SOURCE CODE ONLY")
print(f"   - Python files (src/)")
print(f"   - TypeScript files (ui/src, src-ts/)")
print(f"   - Configuration files")
print(f"   - Smallest size (~50-100 MB)")

print("\n" + "=" * 70)
print("WHAT CAN BE REMOVED SAFELY:")
print("=" * 70)
print("× venv/                - Recreate with: python -m venv venv")
print("× */node_modules/      - Reinstall with: npm install")
print("× aether-rust/target/  - Rebuild with: cargo build")
print("× htmlcov/            - Regenerate with: pytest --cov")
print("× .pytest_cache/      - Auto-recreated on test run")
print(f"\nTotal removable: ~{total_removable:.0f} MB")

print("\n" + "=" * 70)
print("Ab batao kya karna hai:")
print("1. Full project merge (sab kuch as-is)")
print("2. Clean merge (dependencies remove, source code keep)")
print("3. Custom merge (specific folders select karo)")
print("=" * 70)
