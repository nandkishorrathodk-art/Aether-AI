#!/usr/bin/env python3
"""Count files in Aether AI project"""

import os
from pathlib import Path

def count_files(directory="."):
    """Count files excluding certain directories"""
    exclude_dirs = {'.git', 'venv', 'node_modules', '__pycache__', '.pytest_cache'}
    
    total_files = 0
    file_counts = {}
    
    for root, dirs, files in os.walk(directory):
        # Remove excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        # Count files
        total_files += len(files)
        
        # Count by directory
        rel_path = os.path.relpath(root, directory)
        if rel_path == '.':
            rel_path = 'root'
        file_counts[rel_path] = file_counts.get(rel_path, 0) + len(files)
    
    return total_files, file_counts

def main():
    print("Aether AI - File Count Report")
    print("=" * 60)
    
    total, counts = count_files()
    
    # Sort by count
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    
    print(f"\nTotal files (excluding venv, node_modules, .git): {total}")
    print(f"\nTop 20 directories by file count:")
    print("-" * 60)
    
    for i, (path, count) in enumerate(sorted_counts[:20], 1):
        print(f"{i:2}. {path:40} {count:5} files")
    
    # File type analysis
    print(f"\n" + "=" * 60)
    print("File type breakdown:")
    print("-" * 60)
    
    extensions = {}
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in {'.git', 'venv', 'node_modules', '__pycache__'}]
        for file in files:
            ext = Path(file).suffix or 'no extension'
            extensions[ext] = extensions.get(ext, 0) + 1
    
    sorted_ext = sorted(extensions.items(), key=lambda x: x[1], reverse=True)
    for ext, count in sorted_ext[:15]:
        print(f"  {ext:15} {count:5} files")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
