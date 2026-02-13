"""
FastAPI Application

Main web application for NetMonDash with enhanced middleware,
error handling, and lifecycle management.
"""

import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from config import STATIC_DIR, TEMPLATES_DIR, APP_VERSION

logger = logging.getLogger(__name__)


def create_app(
    db_manager=None,
    scanner=None,
    ai_analyzer=None,
    notifier=None,
    lifespan=None,
) -> FastAPI:
    """
    Create and configure FastAPI application.

    Args:
        db_manager: Database manager instance
        scanner: Network scanner instance
        ai_analyzer: AI analyzer instance
        notifier: Notification manager instance
        lifespan: Optional lifespan context manager for startup/shutdown

    Returns:
        Configured FastAPI app
    """
    app = FastAPI(
        title="NetMonDash",
        description="AI-Powered Network Device Monitor Dashboard",
        version=APP_VERSION,
        lifespan=lifespan,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request timing middleware
    @app.middleware("http")
    async def add_timing_header(request: Request, call_next):
        start = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start
        response.headers["X-Response-Time"] = f"{duration:.4f}s"
        return response

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "detail": str(exc)},
        )

    # Mount static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
        logger.info(f"Mounted static files from {STATIC_DIR}")
    else:
        logger.warning(f"Static directory not found: {STATIC_DIR}")

    # Setup Jinja2 templates
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # Store shared resources in app state
    app.state.db_manager = db_manager
    app.state.scanner = scanner
    app.state.ai_analyzer = ai_analyzer
    app.state.notifier = notifier
    app.state.templates = templates

    # Import and include routes
    from .routes import router as api_router
    from .websocket import router as ws_router

    app.include_router(api_router)
    app.include_router(ws_router)

    # Root page
    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        """Root page - overview dashboard."""
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "page": "overview",
                "title": "NetMonDash - Overview",
                "version": APP_VERSION,
            }
        )

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        db_ok = db_manager is not None
        scanner_ok = scanner is not None
        ai_ok = ai_analyzer is not None

        db_info = None
        if db_ok:
            try:
                db_info = db_manager.get_database_info()
            except Exception:
                db_info = {"error": "Failed to query database"}

        return {
            "status": "healthy" if (db_ok and scanner_ok) else "degraded",
            "version": APP_VERSION,
            "components": {
                "database": {"available": db_ok, "info": db_info},
                "scanner": {"available": scanner_ok},
                "ai_analyzer": {"available": ai_ok},
                "notifier": {"available": notifier is not None},
            },
        }

    logger.info(f"FastAPI application v{APP_VERSION} created successfully")
    return app


if __name__ == "__main__":
    import uvicorn

    app = create_app()

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5000,
        log_level="info",
    )
