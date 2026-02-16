#!/usr/bin/env python3
"""
Comprehensive Aether AI Project Analysis
Analyzes all 17,357+ files to identify structure, duplicates, and optimization opportunities
"""

import os
import hashlib
from pathlib import Path
from collections import defaultdict
import json

def get_file_hash(filepath):
    """Calculate MD5 hash of file"""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None

def analyze_project():
    """Comprehensive project analysis"""
    
    # Statistics
    total_files = 0
    total_size = 0
    file_types = defaultdict(int)
    directory_files = defaultdict(int)
    directory_sizes = defaultdict(int)
    large_files = []
    duplicate_hashes = defaultdict(list)
    
    print("=" * 80)
    print("AETHER AI - COMPREHENSIVE PROJECT ANALYSIS")
    print("Analyzing all 17,357+ files...")
    print("=" * 80)
    
    # Walk through all directories
    for root, dirs, files in os.walk("."):
        # Count files per directory
        rel_path = os.path.relpath(root, ".")
        directory_files[rel_path] += len(files)
        
        for file in files:
            filepath = Path(root) / file
            total_files += 1
            
            try:
                size = filepath.stat().st_size
                total_size += size
                directory_sizes[rel_path] += size
                
                # Track file types
                ext = filepath.suffix or 'no_extension'
                file_types[ext] += 1
                
                # Track large files (>10MB)
                if size > 10 * 1024 * 1024:
                    large_files.append((str(filepath), size / (1024*1024)))
                
                # Track duplicates (only for small files to avoid slowdown)
                if size < 1024 * 1024 and size > 0:  # < 1MB
                    file_hash = get_file_hash(filepath)
                    if file_hash:
                        duplicate_hashes[file_hash].append(str(filepath))
                        
            except Exception as e:
                pass
            
            # Progress indicator
            if total_files % 1000 == 0:
                print(f"  Processed {total_files} files...", end='\r')
    
    print(f"\n  Completed analyzing {total_files} files!")
    
    # Generate Report
    print("\n" + "=" * 80)
    print("PROJECT STATISTICS")
    print("=" * 80)
    print(f"Total Files: {total_files:,}")
    print(f"Total Size: {total_size / (1024**3):.2f} GB")
    print(f"Average File Size: {total_size / total_files / 1024:.2f} KB")
    
    # Top directories by file count
    print("\n" + "-" * 80)
    print("TOP 20 DIRECTORIES BY FILE COUNT")
    print("-" * 80)
    sorted_dirs = sorted(directory_files.items(), key=lambda x: x[1], reverse=True)
    for i, (dir_path, count) in enumerate(sorted_dirs[:20], 1):
        size_mb = directory_sizes[dir_path] / (1024**2)
        print(f"{i:2}. {count:6} files | {size_mb:8.1f} MB | {dir_path}")
    
    # Top directories by size
    print("\n" + "-" * 80)
    print("TOP 20 DIRECTORIES BY SIZE")
    print("-" * 80)
    sorted_sizes = sorted(directory_sizes.items(), key=lambda x: x[1], reverse=True)
    for i, (dir_path, size) in enumerate(sorted_sizes[:20], 1):
        size_mb = size / (1024**2)
        file_count = directory_files[dir_path]
        print(f"{i:2}. {size_mb:8.1f} MB | {file_count:6} files | {dir_path}")
    
    # File type analysis
    print("\n" + "-" * 80)
    print("FILE TYPE BREAKDOWN (Top 25)")
    print("-" * 80)
    sorted_types = sorted(file_types.items(), key=lambda x: x[1], reverse=True)
    for i, (ext, count) in enumerate(sorted_types[:25], 1):
        percentage = (count / total_files) * 100
        print(f"{i:2}. {ext:20} {count:6} files ({percentage:5.1f}%)")
    
    # Large files
    print("\n" + "-" * 80)
    print("LARGE FILES (>10MB)")
    print("-" * 80)
    if large_files:
        large_files.sort(key=lambda x: x[1], reverse=True)
        for i, (filepath, size_mb) in enumerate(large_files[:20], 1):
            print(f"{i:2}. {size_mb:8.1f} MB | {filepath}")
    else:
        print("No files larger than 10MB found")
    
    # Duplicates
    print("\n" + "-" * 80)
    print("DUPLICATE FILES (same content)")
    print("-" * 80)
    duplicates = {k: v for k, v in duplicate_hashes.items() if len(v) > 1}
    if duplicates:
        duplicate_count = sum(len(v) - 1 for v in duplicates.values())
        print(f"Found {len(duplicates)} sets of duplicates ({duplicate_count} duplicate files)")
        print("\nTop 10 duplicate sets:")
        sorted_dups = sorted(duplicates.items(), key=lambda x: len(x[1]), reverse=True)
        for i, (hash_val, files) in enumerate(sorted_dups[:10], 1):
            print(f"\n{i}. {len(files)} copies:")
            for file in files[:5]:  # Show first 5
                print(f"   - {file}")
            if len(files) > 5:
                print(f"   ... and {len(files) - 5} more")
    else:
        print("No duplicates found (among files <1MB)")
    
    # Recommendations
    print("\n" + "=" * 80)
    print("RECOMMENDATIONS FOR CLEANUP")
    print("=" * 80)
    
    recommendations = []
    
    # Check for node_modules
    if any('node_modules' in d for d in directory_files.keys()):
        node_size = sum(s for d, s in directory_sizes.items() if 'node_modules' in d)
        recommendations.append(f"• Remove node_modules folders: ~{node_size/(1024**2):.0f} MB")
    
    # Check for Rust target
    if any('target' in d for d in directory_files.keys()):
        target_size = sum(s for d, s in directory_sizes.items() if 'target' in d)
        recommendations.append(f"• Remove Rust target/ folder: ~{target_size/(1024**2):.0f} MB")
    
    # Check for venv
    if any('venv' in d for d in directory_files.keys()):
        venv_size = sum(s for d, s in directory_sizes.items() if 'venv' in d)
        recommendations.append(f"• Virtual environment venv/: {venv_size/(1024**2):.0f} MB (keep for development)")
    
    # Check for test artifacts
    if any('pytest_cache' in d or 'htmlcov' in d for d in directory_files.keys()):
        test_size = sum(s for d, s in directory_sizes.items() if 'pytest_cache' in d or 'htmlcov' in d)
        recommendations.append(f"• Remove test artifacts (.pytest_cache, htmlcov): ~{test_size/(1024**2):.0f} MB")
    
    # Check for .git
    if any('.git' in d for d in directory_files.keys()):
        git_size = sum(s for d, s in directory_sizes.items() if '.git' in d)
        recommendations.append(f"• Git repository (.git): {git_size/(1024**2):.0f} MB (keep for version control)")
    
    if recommendations:
        for rec in recommendations:
            print(rec)
    else:
        print("Project structure looks clean!")
    
    # Potential savings
    removable_size = 0
    if any('node_modules' in d for d in directory_files.keys()):
        removable_size += sum(s for d, s in directory_sizes.items() if 'node_modules' in d)
    if any('target' in d for d in directory_files.keys()):
        removable_size += sum(s for d, s in directory_sizes.items() if 'target' in d)
    if any('pytest_cache' in d or 'htmlcov' in d for d in directory_files.keys()):
        removable_size += sum(s for d, s in directory_sizes.items() if 'pytest_cache' in d or 'htmlcov' in d)
    
    if removable_size > 0:
        print(f"\nPotential space savings: {removable_size/(1024**2):.0f} MB ({removable_size/(1024**3):.2f} GB)")
        print(f"Core project size (after cleanup): {(total_size - removable_size)/(1024**2):.0f} MB")
    
    print("\n" + "=" * 80)
    print("Analysis complete! Report saved to ANALYSIS_REPORT.txt")
    print("=" * 80)
    
    # Save detailed report
    with open("ANALYSIS_REPORT.txt", "w", encoding="utf-8") as f:
        f.write(f"AETHER AI - PROJECT ANALYSIS\n")
        f.write(f"{'=' * 80}\n\n")
        f.write(f"Total Files: {total_files:,}\n")
        f.write(f"Total Size: {total_size / (1024**3):.2f} GB\n\n")
        f.write(f"Top Directories:\n")
        for dir_path, count in sorted_dirs[:50]:
            size_mb = directory_sizes[dir_path] / (1024**2)
            f.write(f"  {count:6} files | {size_mb:8.1f} MB | {dir_path}\n")

if __name__ == "__main__":
    analyze_project()
