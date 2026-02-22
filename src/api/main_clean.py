"""
Aether AI Hybrid Edition - Main FastAPI Application
Combines Aether AI + IronClaw features for ultimate bug bounty hunting + personal assistant
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import time
from contextlib import asynccontextmanager

from src.config import settings
from src.utils.logger import get_logger
from src.intelligence.scheduler import start_intelligence_scheduler, stop_intelligence_scheduler
from src.api.routes import (
    chat, tasks, settings as settings_route, openclaw, security, 
    bugbounty, bugbounty_auto, voice, memory, voice_commands, plugins, developer, discord, workflows, monitor, proactive, control, intelligence, evolution, autonomous, live_testing, v3, n8n, desktop
)
from src.api.hybrid_api import router as hybrid_router
from src.api.security_api import router as security_api_router
from src.api.middleware import rate_limit_middleware

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("🚀 Starting Aether AI Hybrid Edition (Aether + IronClaw)")
    
    # Start live vision monitoring
    try:
        from src.features.live_vision import start_live_monitoring
        start_live_monitoring()
        logger.info("👁️ Live vision monitoring started")
    except Exception as e:
        logger.warning(f"Could not start live vision: {e}")
    
    # Start intelligence scheduler if enabled
    if settings.enable_daily_reports:
        start_intelligence_scheduler()
        logger.info("📊 Intelligence scheduler started")
    
    # Initialize databases (if using IronClaw production stack)
    try:
        from src.db.postgres import db
        from src.db.redis_client import redis_client
        from src.db.vector_store import vector_db
        
        await db.connect()
        await redis_client.connect()
        await vector_db.connect()
        logger.info("🗄️ Production databases connected")
    except Exception as e:
        logger.warning(f"Production databases not configured: {e}")
    
    # Load plugins
    try:
        from src.core.plugins.loader import loader
        loader.load_all_plugins()
        logger.info("🔌 Plugins loaded")
    except Exception as e:
        logger.warning(f"Could not load plugins: {e}")
    
    yield
    
    logger.info("⏸️ Shutting down Aether AI Hybrid Edition")
    
    # Stop live vision monitoring
    try:
        from src.features.live_vision import stop_live_monitoring
        stop_live_monitoring()
    except:
        pass
    
    # Stop intelligence scheduler
    stop_intelligence_scheduler()
    
    # Disconnect databases
    try:
        await db.disconnect()
        await redis_client.disconnect()
        await vector_db.disconnect()
    except:
        pass


app = FastAPI(
    title="Aether AI Hybrid Edition",
    description="Ultimate Bug Bounty Hunter + Personal Assistant (Aether + IronClaw)",
    version="3.5.0-hybrid",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom middleware for process time
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


@app.get("/")
async def root():
    return {
        "name": "Aether AI Hybrid Edition",
        "version": "3.5.0-hybrid",
        "status": "running",
        "description": "Ultimate Bug Bounty Hunter + Personal Assistant",
        "features": [
            "🐛 Bug Bounty Hunting (200k+ CVE database, Nuclei scanner, AI analysis)",
            "🤖 Personal Assistant (Voice, Proactive suggestions, Emotion detection)",
            "👁️ Advanced Vision (Multi-OCR, YOLO v8, Element detection)",
            "🚀 Production Ready (Docker, K8s, Prometheus, Grafana)",
            "🧠 AI Brain (CoT/ToT reasoning, Semantic memory)",
            "📝 Professional Reports (HTML/Markdown/JSON with CVSS)"
        ],
        "endpoints": {
            "chat": "/api/v1/chat",
            "hybrid_vision": "/api/v1/hybrid/vision/analyze",
            "security_cve_search": "/api/v1/security/cve/search",
            "security_nuclei_scan": "/api/v1/security/nuclei/scan",
            "security_ai_scan": "/api/v1/security/ai-scan/analyze-traffic",
            "security_report": "/api/v1/security/report/generate",
            "bugbounty": "/api/v1/bugbounty",
            "voice": "/api/v1/voice",
            "memory": "/api/v1/memory",
            "intelligence": "/api/v1/intelligence",
            "n8n_webhook": "/api/v1/n8n/webhook",
            "health": "/health",
            "docs": "/docs"
        }
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Aether AI Hybrid Edition",
        "version": "3.5.0-hybrid",
        "components": {
            "api": "online",
            "vision": "online",
            "security": "online",
            "ai_brain": "online"
        }
    }


# Include all routers
# Aether AI routes
app.include_router(chat.router)
app.include_router(tasks.router)
app.include_router(settings_route.router)
app.include_router(openclaw.router)
app.include_router(security.router)
app.include_router(bugbounty.router)
app.include_router(bugbounty_auto.router)
app.include_router(voice.router)
app.include_router(memory.router)
app.include_router(voice_commands.router)
app.include_router(plugins.router)
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

# Hybrid routes (Aether + IronClaw)
app.include_router(hybrid_router)
app.include_router(security_api_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main_clean:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
        log_level="info"
    )
