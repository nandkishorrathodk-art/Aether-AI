import os
import shutil
import glob
import json
from typing import List, Optional, Dict, Any, Union
from pathlib import Path
import hashlib
import time

from src.utils.logger import get_logger

logger = get_logger(__name__)


class FileOperationResult:
    def __init__(
        self,
        success: bool,
        message: str = "",
        data: Optional[Any] = None,
        error: Optional[str] = None
    ):
        self.success = success
        self.message = message
        self.data = data
        self.error = error
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "error": self.error
        }
    
    def __repr__(self):
        return f"FileOperationResult(success={self.success}, message='{self.message}')"


class SafeFileOperations:
    DANGEROUS_PATHS = {
        'C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)',
        '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc', '/sys', '/proc'
    }
    
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
    
    def __init__(
        self,
        base_directory: Optional[str] = None,
        max_file_size: int = MAX_FILE_SIZE,
        allowed_extensions: Optional[List[str]] = None
    ):
        self.base_directory = Path(base_directory) if base_directory else Path.cwd()
        self.max_file_size = max_file_size
        self.allowed_extensions = allowed_extensions
        
    def _is_safe_path(self, path: Union[str, Path]) -> bool:
        try:
            resolved_path = Path(path).resolve()
            
            for dangerous_path in self.DANGEROUS_PATHS:
                if str(resolved_path).startswith(dangerous_path):
                    logger.warning(f"Blocked access to dangerous path: {resolved_path}")
                    return False
            
            if self.base_directory:
                try:
                    resolved_path.relative_to(self.base_directory)
                except ValueError:
                    pass
            
            return True
        except Exception as e:
            logger.error(f"Error checking path safety: {e}")
            return False
    
    def _check_extension(self, path: Union[str, Path]) -> bool:
        if not self.allowed_extensions:
            return True
        return Path(path).suffix.lower() in self.allowed_extensions
    
    def read_file(self, file_path: str, encoding: str = 'utf-8') -> FileOperationResult:
        try:
            path = Path(file_path)
            
            if not self._is_safe_path(path):
                return FileOperationResult(
                    success=False,
                    error="Access to this path is not allowed"
                )
            
            if not path.exists():
                return FileOperationResult(
                    success=False,
                    error=f"File not found: {file_path}"
                )
            
            if not path.is_file():
                return FileOperationResult(
                    success=False,
                    error=f"Path is not a file: {file_path}"
                )
            
            file_size = path.stat().st_size
            if file_size > self.max_file_size:
                return FileOperationResult(
                    success=False,
                    error=f"File too large: {file_size} bytes (max: {self.max_file_size})"
                )
            
            with open(path, 'r', encoding=encoding) as f:
                content = f.read()
            
            logger.info(f"Read file: {file_path} ({file_size} bytes)")
            return FileOperationResult(
                success=True,
                message=f"Successfully read {file_size} bytes",
                data=content
            )
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return FileOperationResult(success=False, error=str(e))
    
    def write_file(
        self,
        file_path: str,
        content: str,
        encoding: str = 'utf-8',
        overwrite: bool = False
    ) -> FileOperationResult:
        try:
            path = Path(file_path)
            
            if not self._is_safe_path(path):
                return FileOperationResult(
                    success=False,
                    error="Access to this path is not allowed"
                )
            
            if not self._check_extension(path):
                return FileOperationResult(
                    success=False,
                    error=f"File extension not allowed: {path.suffix}"
                )
            
            if path.exists() and not overwrite:
                return FileOperationResult(
                    success=False,
                    error="File already exists (use overwrite=True to replace)"
                )
            
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding=encoding) as f:
                f.write(content)
            
            logger.info(f"Wrote file: {file_path} ({len(content)} bytes)")
            return FileOperationResult(
                success=True,
                message=f"Successfully wrote {len(content)} bytes to {file_path}"
            )
        except Exception as e:
            logger.error(f"Failed to write file {file_path}: {e}")
            return FileOperationResult(success=False, error=str(e))
    
    def delete_file(self, file_path: str) -> FileOperationResult:
        try:
            path = Path(file_path)
            
            if not self._is_safe_path(path):
                return FileOperationResult(
                    success=False,
                    error="Access to this path is not allowed"
                )
            
            if not path.exists():
                return FileOperationResult(
                    success=False,
                    error=f"File not found: {file_path}"
                )
            
            if path.is_file():
                path.unlink()
            else:
                return FileOperationResult(
                    success=False,
                    error=f"Path is not a file: {file_path}"
                )
            
            logger.info(f"Deleted file: {file_path}")
            return FileOperationResult(
                success=True,
                message=f"Successfully deleted {file_path}"
            )
        except Exception as e:
            logger.error(f"Failed to delete file {file_path}: {e}")
            return FileOperationResult(success=False, error=str(e))
    
    def copy_file(self, source: str, destination: str, overwrite: bool = False) -> FileOperationResult:
        try:
            src_path = Path(source)
            dst_path = Path(destination)
            
            if not self._is_safe_path(src_path) or not self._is_safe_path(dst_path):
                return FileOperationResult(
                    success=False,
                    error="Access to one or more paths is not allowed"
                )
            
            if not src_path.exists():
                return FileOperationResult(
                    success=False,
                    error=f"Source file not found: {source}"
                )
            
            if dst_path.exists() and not overwrite:
                return FileOperationResult(
                    success=False,
                    error="Destination file already exists (use overwrite=True)"
                )
            
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dst_path)
            
            logger.info(f"Copied file: {source} -> {destination}")
            return FileOperationResult(
                success=True,
                message=f"Successfully copied to {destination}"
            )
        except Exception as e:
            logger.error(f"Failed to copy file: {e}")
            return FileOperationResult(success=False, error=str(e))
    
    def move_file(self, source: str, destination: str, overwrite: bool = False) -> FileOperationResult:
        try:
            src_path = Path(source)
            dst_path = Path(destination)
            
            if not self._is_safe_path(src_path) or not self._is_safe_path(dst_path):
                return FileOperationResult(
                    success=False,
                    error="Access to one or more paths is not allowed"
                )
            
            if not src_path.exists():
                return FileOperationResult(
                    success=False,
                    error=f"Source file not found: {source}"
                )
            
            if dst_path.exists() and not overwrite:
                return FileOperationResult(
                    success=False,
                    error="Destination file already exists (use overwrite=True)"
                )
            
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src_path), str(dst_path))
            
            logger.info(f"Moved file: {source} -> {destination}")
            return FileOperationResult(
                success=True,
                message=f"Successfully moved to {destination}"
            )
        except Exception as e:
            logger.error(f"Failed to move file: {e}")
            return FileOperationResult(success=False, error=str(e))
    
    def list_directory(self, directory: str, pattern: str = "*") -> FileOperationResult:
        try:
            dir_path = Path(directory)
            
            if not self._is_safe_path(dir_path):
                return FileOperationResult(
                    success=False,
                    error="Access to this path is not allowed"
                )
            
            if not dir_path.exists():
                return FileOperationResult(
                    success=False,
                    error=f"Directory not found: {directory}"
                )
            
            if not dir_path.is_dir():
                return FileOperationResult(
                    success=False,
                    error=f"Path is not a directory: {directory}"
                )
            
            items = []
            for item in dir_path.glob(pattern):
                stat = item.stat()
                items.append({
                    'name': item.name,
                    'path': str(item),
                    'is_file': item.is_file(),
                    'is_dir': item.is_dir(),
                    'size': stat.st_size,
                    'modified': stat.st_mtime
                })
            
            logger.info(f"Listed directory: {directory} ({len(items)} items)")
            return FileOperationResult(
                success=True,
                message=f"Found {len(items)} items",
                data=items
            )
        except Exception as e:
            logger.error(f"Failed to list directory: {e}")
            return FileOperationResult(success=False, error=str(e))
    
    def create_directory(self, directory: str) -> FileOperationResult:
        try:
            dir_path = Path(directory)
            
            if not self._is_safe_path(dir_path):
                return FileOperationResult(
                    success=False,
                    error="Access to this path is not allowed"
                )
            
            dir_path.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Created directory: {directory}")
            return FileOperationResult(
                success=True,
                message=f"Successfully created directory {directory}"
            )
        except Exception as e:
            logger.error(f"Failed to create directory: {e}")
            return FileOperationResult(success=False, error=str(e))
    
    def delete_directory(self, directory: str, recursive: bool = False) -> FileOperationResult:
        try:
            dir_path = Path(directory)
            
            if not self._is_safe_path(dir_path):
                return FileOperationResult(
                    success=False,
                    error="Access to this path is not allowed"
                )
            
            if not dir_path.exists():
                return FileOperationResult(
                    success=False,
                    error=f"Directory not found: {directory}"
                )
            
            if not dir_path.is_dir():
                return FileOperationResult(
                    success=False,
                    error=f"Path is not a directory: {directory}"
                )
            
            if recursive:
                shutil.rmtree(dir_path)
            else:
                dir_path.rmdir()
            
            logger.info(f"Deleted directory: {directory}")
            return FileOperationResult(
                success=True,
                message=f"Successfully deleted directory {directory}"
            )
        except Exception as e:
            logger.error(f"Failed to delete directory: {e}")
            return FileOperationResult(success=False, error=str(e))
    
    def search_files(
        self,
        directory: str,
        pattern: str,
        recursive: bool = True
    ) -> FileOperationResult:
        try:
            dir_path = Path(directory)
            
            if not self._is_safe_path(dir_path):
                return FileOperationResult(
                    success=False,
                    error="Access to this path is not allowed"
                )
            
            if not dir_path.exists():
                return FileOperationResult(
                    success=False,
                    error=f"Directory not found: {directory}"
                )
            
            if recursive:
                matches = list(dir_path.rglob(pattern))
            else:
                matches = list(dir_path.glob(pattern))
            
            results = []
            for match in matches:
                if match.is_file():
                    stat = match.stat()
                    results.append({
                        'name': match.name,
                        'path': str(match),
                        'size': stat.st_size,
                        'modified': stat.st_mtime
                    })
            
            logger.info(f"Searched files: {directory} with pattern '{pattern}' ({len(results)} matches)")
            return FileOperationResult(
                success=True,
                message=f"Found {len(results)} matching files",
                data=results
            )
        except Exception as e:
            logger.error(f"Failed to search files: {e}")
            return FileOperationResult(success=False, error=str(e))
    
    def get_file_info(self, file_path: str) -> FileOperationResult:
        try:
            path = Path(file_path)
            
            if not self._is_safe_path(path):
                return FileOperationResult(
                    success=False,
                    error="Access to this path is not allowed"
                )
            
            if not path.exists():
                return FileOperationResult(
                    success=False,
                    error=f"File not found: {file_path}"
                )
            
            stat = path.stat()
            info = {
                'name': path.name,
                'path': str(path.resolve()),
                'is_file': path.is_file(),
                'is_dir': path.is_dir(),
                'size': stat.st_size,
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'accessed': stat.st_atime
            }
            
            if path.is_file():
                with open(path, 'rb') as f:
                    file_hash = hashlib.md5(f.read()).hexdigest()
                info['md5'] = file_hash
            
            return FileOperationResult(
                success=True,
                message="File info retrieved",
                data=info
            )
        except Exception as e:
            logger.error(f"Failed to get file info: {e}")
            return FileOperationResult(success=False, error=str(e))
