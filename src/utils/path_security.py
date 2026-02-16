"""
Path Traversal Protection for Aether AI (CVE-5 Fix)
Prevents directory traversal attacks
"""

import os
from pathlib import Path
from typing import Union

class PathSecurityError(Exception):
    """Raised when path traversal is detected"""
    pass


def validate_safe_path(
    user_path: Union[str, Path],
    allowed_base: Union[str, Path],
    allow_absolute: bool = False
) -> Path:
    """
    Validate that user_path is within allowed_base directory
    
    Args:
        user_path: Path provided by user (may contain .., ~, etc.)
        allowed_base: Base directory that user can access
        allow_absolute: If False, reject absolute paths
    
    Returns:
        Validated absolute Path object
    
    Raises:
        PathSecurityError: If path traversal detected
        
    Example:
        >>> safe_path = validate_safe_path("../../etc/passwd", "/home/user/data")
        PathSecurityError: Path traversal detected
        
        >>> safe_path = validate_safe_path("files/doc.txt", "/home/user/data")
        PosixPath('/home/user/data/files/doc.txt')
    """
    # Convert to Path objects
    user_path = Path(user_path)
    allowed_base = Path(allowed_base).resolve()
    
    # Check for absolute path (if not allowed)
    if not allow_absolute and user_path.is_absolute():
        raise PathSecurityError(
            f"Absolute paths not allowed: {user_path}"
        )
    
    # Resolve to absolute path (follows symlinks, resolves ..)
    try:
        if user_path.is_absolute():
            resolved_path = user_path.resolve()
        else:
            resolved_path = (allowed_base / user_path).resolve()
    except (OSError, RuntimeError) as e:
        raise PathSecurityError(f"Invalid path: {user_path} - {e}")
    
    # Check if resolved path is within allowed base
    try:
        # This will raise ValueError if not relative to allowed_base
        resolved_path.relative_to(allowed_base)
    except ValueError:
        raise PathSecurityError(
            f"Path traversal detected: {user_path} resolves outside {allowed_base}"
        )
    
    return resolved_path


def safe_file_read(
    file_path: Union[str, Path],
    base_dir: Union[str, Path],
    max_size_mb: int = 100
) -> bytes:
    """
    Safely read file with path validation and size limit
    
    Args:
        file_path: File to read (relative to base_dir)
        base_dir: Allowed directory
        max_size_mb: Maximum file size in MB
    
    Returns:
        File contents as bytes
        
    Raises:
        PathSecurityError: If path invalid or file too large
        FileNotFoundError: If file doesn't exist
    """
    safe_path = validate_safe_path(file_path, base_dir)
    
    # Check file exists
    if not safe_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not safe_path.is_file():
        raise PathSecurityError(f"Not a file: {file_path}")
    
    # Check file size
    file_size_mb = safe_path.stat().st_size / (1024 * 1024)
    if file_size_mb > max_size_mb:
        raise PathSecurityError(
            f"File too large: {file_size_mb:.2f}MB (max {max_size_mb}MB)"
        )
    
    # Read file
    with open(safe_path, 'rb') as f:
        return f.read()


def safe_file_write(
    file_path: Union[str, Path],
    content: Union[str, bytes],
    base_dir: Union[str, Path],
    max_size_mb: int = 100,
    overwrite: bool = False
) -> Path:
    """
    Safely write file with path validation
    
    Args:
        file_path: File to write (relative to base_dir)
        content: Content to write (str or bytes)
        base_dir: Allowed directory
        max_size_mb: Maximum content size in MB
        overwrite: Allow overwriting existing files
    
    Returns:
        Path object of written file
        
    Raises:
        PathSecurityError: If path invalid or content too large
        FileExistsError: If file exists and overwrite=False
    """
    safe_path = validate_safe_path(file_path, base_dir)
    
    # Check if file exists
    if safe_path.exists() and not overwrite:
        raise FileExistsError(f"File exists (use overwrite=True): {file_path}")
    
    # Check content size
    if isinstance(content, str):
        content_bytes = content.encode('utf-8')
    else:
        content_bytes = content
    
    content_size_mb = len(content_bytes) / (1024 * 1024)
    if content_size_mb > max_size_mb:
        raise PathSecurityError(
            f"Content too large: {content_size_mb:.2f}MB (max {max_size_mb}MB)"
        )
    
    # Create parent directories if needed
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write file
    mode = 'wb' if isinstance(content, bytes) else 'w'
    encoding = None if isinstance(content, bytes) else 'utf-8'
    
    with open(safe_path, mode, encoding=encoding) as f:
        f.write(content if isinstance(content, bytes) else content_bytes.decode('utf-8'))
    
    return safe_path


def safe_list_directory(
    dir_path: Union[str, Path],
    base_dir: Union[str, Path],
    recursive: bool = False,
    max_depth: int = 5
) -> list[Path]:
    """
    Safely list directory contents
    
    Args:
        dir_path: Directory to list (relative to base_dir)
        base_dir: Allowed directory
        recursive: List recursively
        max_depth: Maximum recursion depth
    
    Returns:
        List of Path objects
        
    Raises:
        PathSecurityError: If path invalid
        NotADirectoryError: If not a directory
    """
    safe_path = validate_safe_path(dir_path, base_dir)
    
    if not safe_path.exists():
        raise FileNotFoundError(f"Directory not found: {dir_path}")
    
    if not safe_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {dir_path}")
    
    if recursive:
        if max_depth <= 0:
            return []
        files = []
        for item in safe_path.iterdir():
            files.append(item)
            if item.is_dir():
                # Recursive call with decreased depth
                sub_files = safe_list_directory(
                    item.relative_to(base_dir),
                    base_dir,
                    recursive=True,
                    max_depth=max_depth - 1
                )
                files.extend(sub_files)
        return files
    else:
        return list(safe_path.iterdir())


# Example usage
if __name__ == "__main__":
    # Test path validation
    try:
        # This should FAIL (path traversal)
        safe_path = validate_safe_path("../../etc/passwd", "/home/user/data")
        print(f"ERROR: Should have rejected path traversal!")
    except PathSecurityError as e:
        print(f"[OK] Blocked path traversal: {e}")
    
    try:
        # This should PASS
        safe_path = validate_safe_path("files/document.txt", "/home/user/data")
        print(f"[OK] Allowed safe path: {safe_path}")
    except PathSecurityError as e:
        print(f"ERROR: Should have allowed safe path: {e}")
