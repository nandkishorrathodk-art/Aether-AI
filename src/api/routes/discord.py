"""
Discord bot API routes for Aether AI
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/discord", tags=["discord"])

discord_bot_instance = None


class DiscordBotConfig(BaseModel):
    """Discord bot configuration."""
    token: str
    personality: str = 'friendly'


class DiscordBotStatus(BaseModel):
    """Discord bot status response."""
    running: bool
    personality: Optional[str] = None
    servers: Optional[int] = None
    latency: Optional[float] = None


class PersonalityUpdate(BaseModel):
    """Personality update request."""
    personality: str


@router.post("/start")
async def start_discord_bot(config: DiscordBotConfig, background_tasks: BackgroundTasks):
    """
    Start Discord bot.
    
    Starts the Discord bot with the provided token and personality.
    """
    global discord_bot_instance
    
    if discord_bot_instance and hasattr(discord_bot_instance, 'bot') and not discord_bot_instance.bot.is_closed():
        raise HTTPException(
            status_code=400,
            detail="Discord bot is already running. Stop it first before starting a new instance."
        )
    
    try:
        from src.integrations.discord_bot import create_discord_bot
        from src.cognitive.llm.model_loader import get_model_loader
        
        llm_provider = get_model_loader()
        
        discord_bot_instance = create_discord_bot(
            token=config.token,
            llm_provider=llm_provider,
            personality=config.personality
        )
        
        background_tasks.add_task(discord_bot_instance.start)
        
        return {
            "status": "success",
            "message": "Discord bot started successfully",
            "personality": config.personality
        }
        
    except Exception as e:
        logger.error(f"Error starting Discord bot: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start Discord bot: {str(e)}")


@router.post("/stop")
async def stop_discord_bot():
    """
    Stop Discord bot.
    
    Stops the currently running Discord bot.
    """
    global discord_bot_instance
    
    if not discord_bot_instance:
        raise HTTPException(status_code=400, detail="No Discord bot is currently running")
    
    try:
        await discord_bot_instance.stop()
        discord_bot_instance = None
        
        return {
            "status": "success",
            "message": "Discord bot stopped successfully"
        }
        
    except Exception as e:
        logger.error(f"Error stopping Discord bot: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to stop Discord bot: {str(e)}")


@router.get("/status", response_model=DiscordBotStatus)
async def get_discord_bot_status():
    """
    Get Discord bot status.
    
    Returns the current status of the Discord bot.
    """
    global discord_bot_instance
    
    if not discord_bot_instance:
        return DiscordBotStatus(running=False)
    
    try:
        bot = discord_bot_instance.bot
        
        if bot.is_closed():
            return DiscordBotStatus(running=False)
        
        return DiscordBotStatus(
            running=True,
            personality=discord_bot_instance.personality,
            servers=len(bot.guilds) if bot.guilds else 0,
            latency=round(bot.latency * 1000, 2) if bot.latency else None
        )
        
    except Exception as e:
        logger.error(f"Error getting Discord bot status: {e}")
        return DiscordBotStatus(running=False)


@router.put("/personality")
async def update_personality(personality_update: PersonalityUpdate):
    """
    Update bot personality.
    
    Changes the personality of the running Discord bot.
    """
    global discord_bot_instance
    
    if not discord_bot_instance:
        raise HTTPException(status_code=400, detail="No Discord bot is currently running")
    
    valid_personalities = ['friendly', 'playful', 'professional', 'kawaii', 'tsundere']
    
    if personality_update.personality.lower() not in valid_personalities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid personality. Choose from: {', '.join(valid_personalities)}"
        )
    
    try:
        discord_bot_instance.personality = personality_update.personality.lower()
        
        return {
            "status": "success",
            "message": f"Personality updated to {personality_update.personality}",
            "personality": discord_bot_instance.personality
        }
        
    except Exception as e:
        logger.error(f"Error updating personality: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update personality: {str(e)}")


@router.get("/guilds")
async def get_guilds():
    """
    Get list of guilds (servers).
    
    Returns a list of Discord servers the bot is connected to.
    """
    global discord_bot_instance
    
    if not discord_bot_instance:
        raise HTTPException(status_code=400, detail="No Discord bot is currently running")
    
    try:
        bot = discord_bot_instance.bot
        
        if bot.is_closed():
            raise HTTPException(status_code=400, detail="Discord bot is not connected")
        
        guilds = [
            {
                "id": str(guild.id),
                "name": guild.name,
                "member_count": guild.member_count,
                "icon_url": str(guild.icon.url) if guild.icon else None
            }
            for guild in bot.guilds
        ]
        
        return {
            "status": "success",
            "guilds": guilds,
            "total": len(guilds)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting guilds: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get guilds: {str(e)}")
