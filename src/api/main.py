import os
import time
import threading
from contextlib import asynccontextmanager
<<<<<<< Updated upstream
from src.config import settings
from src.utils.logger import get_logger
from src.intelligence.scheduler import start_intelligence_scheduler, stop_intelligence_scheduler
from src.api.routes import (
    chat, tasks, settings as settings_route, openclaw, security, 
    bugbounty, bugbounty_auto, voice, memory, voice_commands, plugins, developer, discord, workflows, monitor, proactive, control, intelligence, evolution, autonomous, live_testing, v3, n8n, desktop
)
from src.api.middleware import rate_limit_middleware

logger = get_logger(__name__)
=======
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from src.db.postgres import db
from src.db.redis_client import redis_client
from src.db.vector_store import vector_db
from src.core.brain.router import brain_router, RouterRequest
from src.api.routes import plugins
from src.core.plugins.loader import loader
>>>>>>> Stashed changes

# Configure Loguru
logger.add("logs/ironclaw_api.log", rotation="10 MB", retention="1 week", level="INFO")

@asynccontextmanager
async def lifespan(app: FastAPI):
<<<<<<< Updated upstream
    """Application lifespan manager"""
    logger.info("Starting Aether AI application")
    
    # Start live vision monitoring
    try:
        from src.features.live_vision import start_live_monitoring
        start_live_monitoring()
        logger.info("[LIVE VISION] MONITORING STARTED - Real-time screen awareness active")
    except Exception as e:
        logger.warning(f"Could not start live vision: {e}")
    
    if settings.enable_daily_reports:
        start_intelligence_scheduler()
        logger.info("Intelligence scheduler started")
    
    yield
    
    logger.info("Shutting down Aether AI application")
    
    # Stop live vision monitoring
    try:
        from src.features.live_vision import stop_live_monitoring
        stop_live_monitoring()
    except:
        pass
    
    stop_intelligence_scheduler()

=======
    # Startup actions
    await db.connect()
    await redis_client.connect()
    await vector_db.connect()
    # Load plugins on startup
    loader.load_all_plugins()
    yield
    # Shutdown actions
    await db.disconnect()
    await redis_client.disconnect()
    await vector_db.disconnect()
>>>>>>> Stashed changes

app = FastAPI(
    title="Ironclaw Core API",
    description="Next-generation autonomous AI assistant API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for development
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.get("/")
async def root():
<<<<<<< Updated upstream
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "endpoints": {
            "chat": "/api/v1/chat",
            "conversation": "/api/v1/chat/conversation",
            "providers": "/api/v1/chat/providers",
            "cost_stats": "/api/v1/chat/cost-stats",
            "openclaw": "/api/v1/openclaw",
            "openclaw_scrape": "/api/v1/openclaw/scrape",
            "openclaw_navigate": "/api/v1/openclaw/navigate",
            "openclaw_status": "/api/v1/openclaw/status",
            "voice_transcribe": "/api/v1/voice/transcribe",
            "voice_synthesize": "/api/v1/voice/synthesize",
            "voice_devices": "/api/v1/voice/devices",
            "wake_word": "/api/v1/voice/wake-word/status",
            "memory_remember": "/api/v1/memory/remember",
            "memory_recall": "/api/v1/memory/recall",
            "profile": "/api/v1/memory/profile",
            "tasks": "/api/v1/tasks",
            "settings": "/api/v1/settings",
            "bugbounty": "/api/v1/bugbounty",
            "bugbounty_health": "/api/v1/bugbounty/health",
            "intelligence_daily_report": "/api/v1/intelligence/daily-report",
            "intelligence_trends": "/api/v1/intelligence/trends",
            "intelligence_earnings": "/api/v1/intelligence/earnings",
            "discord_start": "/api/v1/discord/start",
            "discord_status": "/api/v1/discord/status",
            "n8n_webhook": "/api/v1/n8n/webhook",
            "n8n_trigger": "/api/v1/n8n/trigger",
            "n8n_actions": "/api/v1/n8n/actions",
            "health": "/health",
            "docs": "/docs"
        }
    }

=======
    return {"message": "Welcome to Ironclaw API", "version": "1.0.0"}
>>>>>>> Stashed changes

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Ironclaw Core",
        "components": {
            "api": "online",
            "db": "pending",
            "redis": "pending",
            "qdrant": "pending"
        }
    }

@app.post("/chat")
async def chat_endpoint(request: RouterRequest):
    result = await brain_router.route_request(request)
    return result

app.include_router(plugins.router)
<<<<<<< Updated upstream
app.include_router(developer.router)
app.include_router(discord.router)
app.include_router(workflows.router)
app.include_router(monitor.router)
app.include_router(proactive.router)
app.include_router(control.router)
app.include_router(intelligence.router)
app.include_router(evolution.router)
app.include_router(autonomous.router)
app.include_router(live_testing.router)
app.include_router(v3.router)
app.include_router(n8n.router)
app.include_router(desktop.router)

=======
>>>>>>> Stashed changes

if __name__ == "__main__":
    import uvicorn
    # Start the server locally for dev
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
