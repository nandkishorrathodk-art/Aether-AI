from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
from contextlib import asynccontextmanager
from src.config import settings
from src.utils.logger import get_logger
from src.intelligence.scheduler import start_intelligence_scheduler, stop_intelligence_scheduler
from src.api.routes import (
    chat, tasks, settings as settings_route, openclaw, security, 
    bugbounty, bugbounty_auto, voice, memory, voice_commands, plugins, developer, discord, workflows, monitor, proactive, control, intelligence, evolution
)
from src.api.middleware import rate_limit_middleware

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting Aether AI application")
    
    if settings.enable_daily_reports:
        start_intelligence_scheduler()
        logger.info("Intelligence scheduler started")
    
    yield
    
    logger.info("Shutting down Aether AI application")
    stop_intelligence_scheduler()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Advanced AI Assistant with Multi-Provider Support",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limiting(request: Request, call_next):
    return await rate_limit_middleware(request, call_next)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    response = await call_next(request)
    
    duration = time.time() - start_time
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Duration: {duration:.3f}s"
    )
    
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )


@app.get("/")
async def root():
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
            "health": "/health",
            "docs": "/docs"
        }
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.app_version,
        "environment": settings.environment
    }


app.include_router(chat.router)
app.include_router(openclaw.router)
app.include_router(security.router)
app.include_router(bugbounty.router)
app.include_router(bugbounty_auto.router)
app.include_router(voice.router)
app.include_router(voice_commands.router)
app.include_router(memory.router)
app.include_router(tasks.router)
app.include_router(settings_route.router)
app.include_router(plugins.router)
app.include_router(developer.router)
app.include_router(discord.router)
app.include_router(workflows.router)
app.include_router(monitor.router)
app.include_router(proactive.router)
app.include_router(control.router)
app.include_router(intelligence.router)
app.include_router(evolution.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.environment == "development",
        log_level=settings.log_level.lower()
    )
