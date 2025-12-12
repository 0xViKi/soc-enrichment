from fastapi import FastAPI


from app.api.v1.routes_health import router as health_router
from app.api.v1.routes_enrich_ip import router as ip_router
from app.api.v1.routes_enrich_domain import router as domain_router
from app.api.v1.routes_enrich_hash import router as hash_router
from app.api.v1.routes_email_analyze import router as email_router
from app.api.v1.routes_email_report import router as email_report_router
from app.api.v1.routes_events import router as events_router

from app.db.init_db import init_db
from app.core.config import settings


app = FastAPI(
    title="SoC Enrichment Platform",
    version="0.1.0",
    description="Backend API for IOC enrichment, phishing analysis, and SOC automation.",
)

@app.on_event("startup")
def on_startup() -> None:
    # Create DB tables if they don't exist (dev only)
    init_db()

@app.get("/", tags=["root"])
async def root() -> dict:
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
    }


# API v1
app.include_router(health_router, prefix="/api/v1")
app.include_router(ip_router, prefix="/api/v1")
app.include_router(domain_router, prefix="/api/v1")
app.include_router(hash_router, prefix="/api/v1")
app.include_router(email_router, prefix="/api/v1")
app.include_router(email_report_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
