from fastapi import APIRouter, HTTPException
from typing import Optional
import json
import os
from datetime import datetime
from pathlib import Path
from src.api.schemas.settings import (
    Settings,
    SettingsUpdateRequest,
    SettingsResponse,
    VoiceSettings,
    AISettings,
    MemorySettings,
    SystemSettings
)
from src.config import settings as app_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

SETTINGS_FILE = Path("data/user_settings.json")


class SettingsManager:
    def __init__(self):
        self.settings_file = SETTINGS_FILE
        self.settings_file.parent.mkdir(parents=True, exist_ok=True)
        self._current_settings = self._load_settings()
    
    def _load_settings(self) -> Settings:
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r') as f:
                    data = json.load(f)
                    return Settings(**data.get("settings", {}))
            except Exception as e:
                logger.error(f"Error loading settings: {e}")
        
        return Settings()
    
    def _save_settings(self, settings: Settings) -> bool:
        try:
            data = {
                "settings": settings.model_dump(),
                "last_updated": datetime.now().isoformat()
            }
            
            with open(self.settings_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self._current_settings = settings
            logger.info("Settings saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            return False
    
    def get_settings(self) -> tuple[Settings, Optional[str]]:
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r') as f:
                    data = json.load(f)
                    return self._current_settings, data.get("last_updated")
            except Exception as e:
                logger.error(f"Error reading settings timestamp: {e}")
        
        return self._current_settings, None
    
    def update_settings(self, updates: SettingsUpdateRequest) -> Settings:
        current = self._current_settings
        
        if updates.voice:
            current.voice = updates.voice
        
        if updates.ai:
            current.ai = updates.ai
        
        if updates.memory:
            current.memory = updates.memory
        
        if updates.system:
            current.system = updates.system
        
        if updates.custom:
            current.custom.update(updates.custom)
        
        if self._save_settings(current):
            return current
        else:
            raise Exception("Failed to save settings")
    
    def reset_settings(self) -> Settings:
        default_settings = Settings()
        if self._save_settings(default_settings):
            return default_settings
        else:
            raise Exception("Failed to reset settings")
    
    def get_voice_settings(self) -> VoiceSettings:
        return self._current_settings.voice
    
    def get_ai_settings(self) -> AISettings:
        return self._current_settings.ai
    
    def get_memory_settings(self) -> MemorySettings:
        return self._current_settings.memory
    
    def get_system_settings(self) -> SystemSettings:
        return self._current_settings.system


settings_manager = SettingsManager()


@router.get("/", response_model=SettingsResponse)
async def get_settings():
    try:
        settings, last_updated = settings_manager.get_settings()
        
        return SettingsResponse(
            settings=settings,
            last_updated=last_updated
        )
        
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/", response_model=SettingsResponse)
async def update_settings(request: SettingsUpdateRequest):
    try:
        updated_settings = settings_manager.update_settings(request)
        
        return SettingsResponse(
            settings=updated_settings,
            last_updated=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reset", response_model=SettingsResponse)
async def reset_settings():
    try:
        default_settings = settings_manager.reset_settings()
        
        return SettingsResponse(
            settings=default_settings,
            last_updated=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error resetting settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/voice", response_model=VoiceSettings)
async def get_voice_settings():
    try:
        return settings_manager.get_voice_settings()
        
    except Exception as e:
        logger.error(f"Error getting voice settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/voice", response_model=VoiceSettings)
async def update_voice_settings(voice_settings: VoiceSettings):
    try:
        request = SettingsUpdateRequest(voice=voice_settings)
        updated_settings = settings_manager.update_settings(request)
        return updated_settings.voice
        
    except Exception as e:
        logger.error(f"Error updating voice settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ai", response_model=AISettings)
async def get_ai_settings():
    try:
        return settings_manager.get_ai_settings()
        
    except Exception as e:
        logger.error(f"Error getting AI settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/ai", response_model=AISettings)
async def update_ai_settings(ai_settings: AISettings):
    try:
        request = SettingsUpdateRequest(ai=ai_settings)
        updated_settings = settings_manager.update_settings(request)
        return updated_settings.ai
        
    except Exception as e:
        logger.error(f"Error updating AI settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/memory", response_model=MemorySettings)
async def get_memory_settings():
    try:
        return settings_manager.get_memory_settings()
        
    except Exception as e:
        logger.error(f"Error getting memory settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/memory", response_model=MemorySettings)
async def update_memory_settings(memory_settings: MemorySettings):
    try:
        request = SettingsUpdateRequest(memory=memory_settings)
        updated_settings = settings_manager.update_settings(request)
        return updated_settings.memory
        
    except Exception as e:
        logger.error(f"Error updating memory settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/system", response_model=SystemSettings)
async def get_system_settings():
    try:
        return settings_manager.get_system_settings()
        
    except Exception as e:
        logger.error(f"Error getting system settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/system", response_model=SystemSettings)
async def update_system_settings(system_settings: SystemSettings):
    try:
        request = SettingsUpdateRequest(system=system_settings)
        updated_settings = settings_manager.update_settings(request)
        return updated_settings.system
        
    except Exception as e:
        logger.error(f"Error updating system settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/export")
async def export_settings():
    try:
        settings, last_updated = settings_manager.get_settings()
        
        return {
            "settings": settings.model_dump(),
            "last_updated": last_updated,
            "export_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error exporting settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/import", response_model=SettingsResponse)
async def import_settings(settings_data: dict):
    try:
        imported_settings = Settings(**settings_data.get("settings", settings_data))
        
        if settings_manager._save_settings(imported_settings):
            return SettingsResponse(
                settings=imported_settings,
                last_updated=datetime.now().isoformat()
            )
        else:
            raise HTTPException(status_code=500, detail="Failed to import settings")
        
    except Exception as e:
        logger.error(f"Error importing settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))
