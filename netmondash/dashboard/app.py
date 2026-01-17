"""
FastAPI Application

Main web application for NetMonDash.
"""

import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from config import STATIC_DIR, TEMPLATES_DIR

logger = logging.getLogger(__name__)


def create_app(
    db_manager=None,
    scanner=None,
    ai_analyzer=None,
    notifier=None,
) -> FastAPI:
    """
    Create and configure FastAPI application.

    Args:
        db_manager: Database manager instance
        scanner: Network scanner instance
        ai_analyzer: AI analyzer instance
        notifier: Notification manager instance

    Returns:
        Configured FastAPI app
    """
    app = FastAPI(
        title="NetMonDash",
        description="AI-Powered Network Device Monitor Dashboard",
        version="1.0.0",
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
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

    # Root page - redirect to overview
    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        """Root page - overview dashboard."""
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "page": "overview",
                "title": "NetMonDash - Overview",
            }
        )

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "database": db_manager is not None,
            "scanner": scanner is not None,
            "ai": ai_analyzer is not None,
        }

    logger.info("FastAPI application created successfully")
    return app


if __name__ == "__main__":
    # For development testing
    import uvicorn

    app = create_app()

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5000,
        log_level="info",
    )
