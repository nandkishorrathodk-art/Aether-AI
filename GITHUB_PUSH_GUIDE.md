# GitHub Push Guide - Aether AI

## Issue: Push Timeout

The `git push` command is timing out because the repository is very large. Here are solutions:

## Solution 1: Push in Background (Recommended)

```bash
# Start push in background and let it run
start /B git push origin nitro-v-f99b

# Or use PowerShell
Start-Job -ScriptBlock { cd "C:\Users\nandk\.zenflow\worktrees\nitro-v-f99b"; git push origin nitro-v-f99b }
```

## Solution 2: Increase Git Buffer Size

```bash
# Increase post buffer to 500MB
git config http.postBuffer 524288000

# Then push
git push origin nitro-v-f99b
```

## Solution 3: Push with Compression Disabled

```bash
# Disable compression (faster for large repos)
git config --global core.compression 0

# Push
git push origin nitro-v-f99b

# Re-enable compression after
git config --global core.compression -1
```

## Solution 4: Check Large Files

```powershell
# Find files larger than 10MB
Get-ChildItem -Recurse -File | Where-Object {$_.Length -gt 10MB} | 
    Sort-Object Length -Descending | 
    Select-Object FullName, @{Name='SizeMB';Expression={[math]::Round($_.Length/1MB,2)}}
```

If you have large binary files, consider:
- Adding them to `.gitignore`
- Using Git LFS: `git lfs track "*.bin"`

## Solution 5: Manual Steps

```bash
# 1. Set larger buffer
git config http.postBuffer 524288000

# 2. Set longer timeout
git config http.lowSpeedLimit 0
git config http.lowSpeedTime 999999

# 3. Push
git push origin nitro-v-f99b --verbose
```

## Current Status

- **Remote**: `https://github.com/nandkishorrathodk-art/Aether-AI.git`
- **Branch**: `nitro-v-f99b`
- **Status**: Working tree clean, ready to push
- **Issue**: Push timing out after ~2-3 minutes

## Quick Fix Command

```bash
git config http.postBuffer 524288000 && git config http.lowSpeedLimit 0 && git push origin nitro-v-f99b
```

## Alternative: GitHub Desktop

If command line push continues failing:
1. Download GitHub Desktop
2. Add this repository
3. Use GUI to push (handles large repos better)

## Alternative: Split History

If repository is too large, consider creating a fresh repository with current state only:

```bash
# Create fresh branch with current state only
git checkout --orphan fresh-start
git add -A
git commit -m "Aether AI - Initial Release"
git push origin fresh-start:main --force
```
