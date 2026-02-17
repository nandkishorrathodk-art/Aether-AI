import json
import aiofiles
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime

from src.control.models import (
    ActionType,
    ControlAction,
    PermissionRule,
    AuditLogEntry,
    ActionResult
)
from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PermissionManager:
    
    def __init__(self):
        self.audit_log_path = settings.pc_control_audit_log
        self.permissions_path = settings.pc_control_audit_log.parent / "permissions.json"
        self._ensure_paths()
        self._load_permissions()
    
    def _ensure_paths(self):
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.permissions_path.exists():
            self._create_default_permissions()
    
    def _create_default_permissions(self):
        allowed_actions = settings.get_pc_control_allowed_actions()
        
        default_permissions = {
            action_type.value: {
                "allowed": action_type.value in allowed_actions,
                "require_confirmation": settings.pc_control_require_confirmation,
                "reason": "Default permission"
            }
            for action_type in ActionType
        }
        
        with open(self.permissions_path, 'w') as f:
            json.dump(default_permissions, f, indent=2)
    
    def _load_permissions(self):
        if not self.permissions_path.exists():
            self._create_default_permissions()
        
        try:
            with open(self.permissions_path, 'r') as f:
                perms_data = json.load(f)
            
            self.permissions: Dict[ActionType, PermissionRule] = {}
            for action_str, perm_dict in perms_data.items():
                try:
                    action_type = ActionType(action_str)
                    self.permissions[action_type] = PermissionRule(
                        action_type=action_type,
                        **perm_dict
                    )
                except ValueError:
                    logger.warning(f"Unknown action type in permissions: {action_str}")
        except Exception as e:
            logger.error(f"Failed to load permissions: {e}")
            self.permissions = {}
    
    def is_action_allowed(self, action: ControlAction) -> bool:
        if not settings.enable_pc_control:
            logger.warning("PC control is disabled in settings")
            return False
        
        permission = self.permissions.get(action.action_type)
        if permission is None:
            logger.warning(f"No permission rule for {action.action_type}")
            return False
        
        return permission.allowed
    
    def requires_confirmation(self, action: ControlAction) -> bool:
        if action.require_confirmation:
            return True
        
        permission = self.permissions.get(action.action_type)
        if permission is None:
            return True
        
        return permission.require_confirmation
    
    async def log_action(self, action: ControlAction, result: ActionResult, user_id: Optional[str] = None):
        entry = AuditLogEntry(
            action_type=action.action_type,
            parameters=action.parameters,
            success=result.success,
            confirmed=result.confirmed,
            user_id=user_id,
            error=result.error
        )
        
        log_string = entry.to_log_string()
        
        try:
            async with aiofiles.open(self.audit_log_path, 'a') as f:
                await f.write(log_string + '\n')
            logger.info(f"Action logged: {action.action_type.value}")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def get_blacklisted_actions(self) -> Set[ActionType]:
        return {
            action_type for action_type, perm in self.permissions.items()
            if not perm.allowed
        }
    
    def get_whitelisted_actions(self) -> Set[ActionType]:
        return {
            action_type for action_type, perm in self.permissions.items()
            if perm.allowed
        }
    
    def update_permission(self, action_type: ActionType, allowed: bool, require_confirmation: bool = True, reason: Optional[str] = None):
        self.permissions[action_type] = PermissionRule(
            action_type=action_type,
            allowed=allowed,
            require_confirmation=require_confirmation,
            reason=reason
        )
        self._save_permissions()
    
    def _save_permissions(self):
        perms_data = {
            action_type.value: {
                "allowed": perm.allowed,
                "require_confirmation": perm.require_confirmation,
                "reason": perm.reason
            }
            for action_type, perm in self.permissions.items()
        }
        
        try:
            with open(self.permissions_path, 'w') as f:
                json.dump(perms_data, f, indent=2)
            logger.info("Permissions saved successfully")
        except Exception as e:
            logger.error(f"Failed to save permissions: {e}")
    
    async def get_recent_logs(self, limit: int = 100) -> List[str]:
        if not self.audit_log_path.exists():
            return []
        
        try:
            async with aiofiles.open(self.audit_log_path, 'r') as f:
                lines = await f.readlines()
            return lines[-limit:] if len(lines) > limit else lines
        except Exception as e:
            logger.error(f"Failed to read audit logs: {e}")
            return []
    
    def get_all_permissions(self) -> Dict[str, Dict]:
        return {
            action_type.value: {
                "allowed": perm.allowed,
                "require_confirmation": perm.require_confirmation,
                "reason": perm.reason
            }
            for action_type, perm in self.permissions.items()
        }
