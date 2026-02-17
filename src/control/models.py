from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class ActionType(str, Enum):
    MOUSE_CLICK = "mouse_click"
    MOUSE_MOVE = "mouse_move"
    KEYBOARD_TYPE = "keyboard_type"
    KEYBOARD_PRESS = "keyboard_press"
    APP_LAUNCH = "app_launch"
    APP_CLOSE = "app_close"


class MouseButton(str, Enum):
    LEFT = "left"
    RIGHT = "right"
    MIDDLE = "middle"


class ControlAction(BaseModel):
    action_type: ActionType
    parameters: Dict[str, Any] = Field(default_factory=dict)
    require_confirmation: bool = True
    description: Optional[str] = None
    
    class Config:
        use_enum_values = True


class ActionResult(BaseModel):
    success: bool
    action_type: ActionType
    timestamp: datetime = Field(default_factory=datetime.now)
    message: Optional[str] = None
    error: Optional[str] = None
    executed: bool = False
    confirmed: bool = False
    
    class Config:
        use_enum_values = True


class PermissionRule(BaseModel):
    action_type: ActionType
    allowed: bool
    require_confirmation: bool = True
    reason: Optional[str] = None
    
    class Config:
        use_enum_values = True


class AuditLogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    action_type: ActionType
    parameters: Dict[str, Any]
    success: bool
    confirmed: bool
    user_id: Optional[str] = None
    error: Optional[str] = None
    
    class Config:
        use_enum_values = True
    
    def to_log_string(self) -> str:
        status = "SUCCESS" if self.success else "FAILED"
        confirmed_str = "CONFIRMED" if self.confirmed else "AUTO"
        action_type_str = self.action_type.value if isinstance(self.action_type, ActionType) else self.action_type
        return (
            f"[{self.timestamp.isoformat()}] {status} | {confirmed_str} | "
            f"{action_type_str} | {self.parameters} | "
            f"{self.error if self.error else 'OK'}"
        )
