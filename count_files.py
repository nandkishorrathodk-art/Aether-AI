#!/usr/bin/env python3
"""Count files in Aether AI project"""

import os
from pathlib import Path
from collections import defaultdict

def count_files():
    project_root = Path.cwd()
    
    # Exclude directories
    exclude_dirs = {'venv', 'node_modules', '.git', '__pycache__', 'dist', 'build', 'htmlcov', '.pytest_cache', 'security_backups'}
    
    total_files = 0
    total_size = 0
    by_extension = defaultdict(lambda: {'count': 0, 'size': 0})
    
    print("=" * 70)
    print("AETHER AI - FILE COUNT ANALYSIS")
    print("=" * 70)
    
    for root, dirs, files in os.walk(project_root):
        # Remove excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            file_path = Path(root) / file
            try:
                size = file_path.stat().st_size
                ext = file_path.suffix.lower() or 'no extension'
                
                total_files += 1
                total_size += size
                by_extension[ext]['count'] += 1
                by_extension[ext]['size'] += size
            except:
                pass
    
    # Sort by count
    sorted_exts = sorted(by_extension.items(), key=lambda x: x[1]['count'], reverse=True)
    
    print(f"\n[+] Total Files: {total_files:,}")
    print(f"[+] Total Size: {total_size / (1024*1024):.2f} MB")
    
    print("\n" + "=" * 70)
    print("FILE BREAKDOWN BY TYPE")
    print("=" * 70)
    print(f"{'Extension':<20} {'Count':<10} {'Size (MB)':<15} {'%':<10}")
    print("-" * 70)
    
    for ext, data in sorted_exts[:20]:  # Top 20
        count = data['count']
        size_mb = data['size'] / (1024*1024)
        percentage = (count / total_files) * 100
        print(f"{ext:<20} {count:<10} {size_mb:<15.2f} {percentage:<10.1f}%")
    
    # Key categories
    print("\n" + "=" * 70)
    print("KEY CATEGORIES")
    print("=" * 70)
    
    categories = {
        'Python Files': ['.py'],
        'JavaScript/TypeScript': ['.js', '.jsx', '.ts', '.tsx'],
        'Documentation': ['.md', '.txt'],
        'Configuration': ['.json', '.yaml', '.yml', '.toml', '.ini', '.env'],
        'C/C++': ['.c', '.cpp', '.h', '.hpp'],
        'C#': ['.cs'],
        'Swift': ['.swift'],
        'Rust': ['.rs'],
        'Images': ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg'],
        'Web': ['.html', '.css', '.scss'],
        'Data': ['.csv', '.db', '.sqlite', '.sqlite3'],
        'Archives': ['.zip', '.tar', '.gz'],
    }
    
    for category, extensions in categories.items():
        cat_count = sum(by_extension[ext]['count'] for ext in extensions)
        cat_size = sum(by_extension[ext]['size'] for ext in extensions)
        
        if cat_count > 0:
            print(f"\n{category}:")
            print(f"  Files: {cat_count:,}")
            print(f"  Size: {cat_size / (1024*1024):.2f} MB")
            
            for ext in extensions:
                if by_extension[ext]['count'] > 0:
                    print(f"    {ext}: {by_extension[ext]['count']} files")
    
    # Largest files
    print("\n" + "=" * 70)
    print("LARGEST FILES (Top 10)")
    print("=" * 70)
    
    all_files = []
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            file_path = Path(root) / file
            try:
                size = file_path.stat().st_size
                all_files.append((file_path, size))
            except:
                pass
    
    all_files.sort(key=lambda x: x[1], reverse=True)
    
    for i, (fpath, size) in enumerate(all_files[:10], 1):
        rel_path = fpath.relative_to(project_root)
        size_mb = size / (1024*1024)
        print(f"{i:2}. {size_mb:8.2f} MB - {rel_path}")
    
    print("\n" + "=" * 70)
    print("PROJECT STATISTICS")
    print("=" * 70)
    
    # Count lines of code
    code_extensions = {'.py', '.js', '.jsx', '.ts', '.tsx', '.c', '.cpp', '.cs', '.rs', '.swift'}
    total_lines = 0
    code_files = 0
    
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            if Path(file).suffix.lower() in code_extensions:
                try:
                    with open(Path(root) / file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = len(f.readlines())
                        total_lines += lines
                        code_files += 1
                except:
                    pass
    
    print(f"\n[+] Code Files: {code_files:,}")
    print(f"[+] Total Lines of Code: {total_lines:,}")
    print(f"[+] Average Lines per File: {total_lines // code_files if code_files > 0 else 0:,}")
    
    # Documentation
    doc_files = by_extension['.md']['count']
    print(f"\n[+] Documentation Files (.md): {doc_files}")
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    count_files()
