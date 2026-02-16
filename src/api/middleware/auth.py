"""
Authentication Middleware for Aether AI
Implements JWT-based authentication
"""

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
from typing import Optional

security = HTTPBearer(auto_error=False)

# Simple API key authentication
# SECURITY FIX CVE-3: No default API key
api_key = os.getenv("AETHER_API_KEY")
if not api_key:
    raise ValueError("AETHER_API_KEY environment variable must be set!")
VALID_API_KEYS = {api_key}

async def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security)
) -> str:
    """
    Verify authentication token
    
    For development: Use Bearer token matching AETHER_API_KEY env var
    For production: Implement JWT validation
    """
    
    # REMOVED: Development mode bypass (SECURITY FIX CVE-2)
    # Authentication is now REQUIRED in all environments
    
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = credentials.credentials
    
    # Simple API key check
    if token not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return "authenticated-user"

# Optional: Add to routes with:
# from fastapi import Depends
# from src.api.middleware.auth import verify_token
#
# @router.get("/protected", dependencies=[Depends(verify_token)])
# async def protected_endpoint():
#     return {"message": "You are authenticated!"}
