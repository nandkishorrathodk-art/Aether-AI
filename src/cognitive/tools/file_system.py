"""
File System Tool - File Operations for Jarvis

Gives Aether ability to work with files:
- Read files (code, configs, data)
- Write files (reports, code, notes)
- List directories
- Search files
- Safe operations with sandboxing

Boss, ab Aether files ke saath kaam kar sakta hai!
"""

import logging
import os
from typing import List, Dict, Optional, Any
from pathlib import Path
import json
import re

logger = logging.getLogger(__name__)


class FileSystemTool:
    """
    Safe file system operations for AI agent
    
    Sandboxed to specific directories for safety.
    Prevents accessing system files or dangerous locations.
    """
    
    def __init__(
        self,
        allowed_directories: Optional[List[str]] = None,
        workspace_dir: Optional[str] = None
    ):
        """
        Initialize file system tool
        
        Args:
            allowed_directories: Directories agent can access (default: data/, reports/)
            workspace_dir: Main workspace directory (default: current directory)
        """
        self.workspace_dir = Path(workspace_dir or os.getcwd())
        
        if allowed_directories is None:
            self.allowed_dirs = [
                self.workspace_dir / "data",
                self.workspace_dir / "reports",
                self.workspace_dir / "logs",
                self.workspace_dir / "tmp"
            ]
        else:
            self.allowed_dirs = [Path(d) for d in allowed_directories]
        
        for directory in self.allowed_dirs:
            directory.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"FileSystemTool initialized - Workspace: {self.workspace_dir}")
    
    def _is_safe_path(self, path: Path) -> bool:
        """Check if path is within allowed directories"""
        try:
            resolved = path.resolve()
            
            for allowed_dir in self.allowed_dirs:
                try:
                    resolved.relative_to(allowed_dir.resolve())
                    return True
                except ValueError:
                    continue
            
            return False
        except Exception:
            return False
    
    def read_file(self, file_path: str, encoding: str = "utf-8") -> Optional[str]:
        """
        Read file contents
        
        Args:
            file_path: Path to file
            encoding: Text encoding (default: utf-8)
            
        Returns:
            File contents as string or None
        """
        path = Path(file_path)
        
        if not self._is_safe_path(path):
            logger.error(f"Access denied to: {file_path}")
            return None
        
        try:
            with open(path, 'r', encoding=encoding) as f:
                content = f.read()
            
            logger.info(f"Read file: {file_path} ({len(content)} chars)")
            return content
        
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return None
    
    def write_file(
        self,
        file_path: str,
        content: str,
        encoding: str = "utf-8",
        overwrite: bool = False
    ) -> bool:
        """
        Write content to file
        
        Args:
            file_path: Path to file
            content: Content to write
            encoding: Text encoding
            overwrite: Allow overwriting existing files
            
        Returns:
            True if successful
        """
        path = Path(file_path)
        
        if not self._is_safe_path(path):
            logger.error(f"Access denied to: {file_path}")
            return False
        
        if path.exists() and not overwrite:
            logger.error(f"File exists and overwrite=False: {file_path}")
            return False
        
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding=encoding) as f:
                f.write(content)
            
            logger.info(f"Wrote file: {file_path} ({len(content)} chars)")
            return True
        
        except Exception as e:
            logger.error(f"Failed to write {file_path}: {e}")
            return False
    
    def list_directory(self, directory: str = ".") -> List[Dict[str, Any]]:
        """
        List files in directory
        
        Args:
            directory: Directory path
            
        Returns:
            List of file info dicts
        """
        path = Path(directory)
        
        if not self._is_safe_path(path):
            logger.error(f"Access denied to: {directory}")
            return []
        
        try:
            entries = []
            
            for item in path.iterdir():
                entries.append({
                    "name": item.name,
                    "path": str(item),
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                    "modified": item.stat().st_mtime
                })
            
            logger.info(f"Listed directory: {directory} ({len(entries)} items)")
            return entries
        
        except Exception as e:
            logger.error(f"Failed to list {directory}: {e}")
            return []
    
    def search_files(
        self,
        pattern: str,
        directory: str = ".",
        recursive: bool = True
    ) -> List[str]:
        """
        Search for files matching pattern
        
        Args:
            pattern: Glob pattern (e.g., "*.py", "**/*.txt")
            directory: Directory to search
            recursive: Search subdirectories
            
        Returns:
            List of matching file paths
        """
        path = Path(directory)
        
        if not self._is_safe_path(path):
            logger.error(f"Access denied to: {directory}")
            return []
        
        try:
            if recursive:
                matches = list(path.rglob(pattern))
            else:
                matches = list(path.glob(pattern))
            
            file_paths = [str(m) for m in matches if m.is_file()]
            
            logger.info(f"Found {len(file_paths)} files matching '{pattern}'")
            return file_paths
        
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    def file_exists(self, file_path: str) -> bool:
        """Check if file exists"""
        path = Path(file_path)
        
        if not self._is_safe_path(path):
            return False
        
        return path.exists() and path.is_file()
    
    def delete_file(self, file_path: str, force: bool = False) -> bool:
        """
        Delete a file
        
        Args:
            file_path: Path to file
            force: Force deletion without confirmation
            
        Returns:
            True if deleted
        """
        path = Path(file_path)
        
        if not self._is_safe_path(path):
            logger.error(f"Access denied to: {file_path}")
            return False
        
        if not force:
            logger.warning(f"Delete requires force=True: {file_path}")
            return False
        
        try:
            path.unlink()
            logger.info(f"Deleted file: {file_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to delete {file_path}: {e}")
            return False
    
    def read_json(self, file_path: str) -> Optional[Dict]:
        """Read and parse JSON file"""
        content = self.read_file(file_path)
        
        if content is None:
            return None
        
        try:
            data = json.loads(content)
            logger.info(f"Parsed JSON from: {file_path}")
            return data
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            return None
    
    def write_json(
        self,
        file_path: str,
        data: Dict,
        indent: int = 2,
        overwrite: bool = False
    ) -> bool:
        """Write data as JSON file"""
        try:
            content = json.dumps(data, indent=indent)
            return self.write_file(file_path, content, overwrite=overwrite)
        except Exception as e:
            logger.error(f"Failed to serialize JSON: {e}")
            return False
    
    def get_file_info(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get detailed file information"""
        path = Path(file_path)
        
        if not self._is_safe_path(path):
            logger.error(f"Access denied to: {file_path}")
            return None
        
        if not path.exists():
            return None
        
        try:
            stat = path.stat()
            
            return {
                "name": path.name,
                "path": str(path),
                "type": "directory" if path.is_dir() else "file",
                "size": stat.st_size,
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "extension": path.suffix if path.is_file() else None
            }
        
        except Exception as e:
            logger.error(f"Failed to get info for {file_path}: {e}")
            return None


_file_system_instance = None

def get_file_system() -> FileSystemTool:
    """Get global file system tool instance"""
    global _file_system_instance
    
    if _file_system_instance is None:
        _file_system_instance = FileSystemTool()
    
    return _file_system_instance


logger.info("File System Tool loaded")
