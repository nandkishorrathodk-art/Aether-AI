"""
Security Middleware - Enhanced Authentication & Validation

Provides security controls for dangerous endpoints.
"""

from fastapi import HTTPException, Security, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import re
from urllib.parse import urlparse

from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)

security_scheme = HTTPBearer()


def validate_api_key(credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    """
    Validate API key for dangerous operations
    
    Requires Bearer token matching AETHER_API_KEY environment variable
    """
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Missing authentication credentials"
        )
    
    expected_key = settings.secret_key
    if credentials.credentials != expected_key:
        logger.warning(f"Invalid API key attempt: {credentials.credentials[:10]}...")
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    
    return credentials.credentials


def validate_target_domain(target: str) -> str:
    """
    Validate target domain to prevent SSRF and localhost attacks
    
    Args:
        target: Target domain or URL
        
    Returns:
        Validated target
        
    Raises:
        HTTPException: If target is invalid or dangerous
    """
    # Remove protocol if present
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    
    # Remove port
    target = target.split(':')[0]
    
    # Blocked patterns (SSRF prevention)
    blocked_patterns = [
        r'^localhost$',
        r'^127\.',
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^169\.254\.',
        r'^::1$',
        r'^0\.0\.0\.0$',
        r'\.local$',
        r'\.internal$',
    ]
    
    for pattern in blocked_patterns:
        if re.match(pattern, target, re.IGNORECASE):
            logger.warning(f"Blocked dangerous target: {target}")
            raise HTTPException(
                status_code=400,
                detail=f"Target '{target}' is not allowed. Cannot target localhost, internal networks, or private IPs."
            )
    
    # Must be valid domain format
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, target):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target domain: {target}"
        )
    
    logger.info(f"✅ Target validated: {target}")
    return target


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent injection attacks
    
    Args:
        text: Input text
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    if len(text) > max_length:
        raise HTTPException(
            status_code=400,
            detail=f"Input too long. Maximum {max_length} characters allowed."
        )
    
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '`', '$', '|', ';', '&']
    for char in dangerous_chars:
        if char in text:
            logger.warning(f"Removed dangerous character from input: {char}")
            text = text.replace(char, '')
    
    return text.strip()


def check_autonomous_enabled():
    """Check if autonomous mode is enabled"""
    if not getattr(settings, 'enable_autonomous_mode', False):
        raise HTTPException(
            status_code=403,
            detail="Autonomous mode is disabled in settings. Enable ENABLE_AUTONOMOUS_MODE in .env"
        )
