from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable
import uvicorn
import logging

from app.core.config import settings
from app.api.v1.endpoints import auth, users
from app.core.database import engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="ASYV Information System API",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Custom middleware for database error handling
class DatabaseErrorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        try:
            response = await call_next(request)
            return response
        except SQLAlchemyError as e:
            logger.error(f"Database error: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={"detail": "A database error occurred. Please try again later."}
            )
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={"detail": "An unexpected error occurred"}
            )

# Add middleware
app.add_middleware(DatabaseErrorMiddleware)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    # Include routers
    app.include_router(
        auth.router,
        prefix=f"{settings.API_V1_STR}/auth",
        tags=["authentication"]
    )

    app.include_router(
        users.router,
        prefix=f"{settings.API_V1_STR}/users",
        tags=["users"]
    )
    logger.info("Successfully initialized API routers")
except Exception as e:
    logger.error(f"Error initializing API routers: {str(e)}")
    raise

@app.get("/")
async def root():
    """Root endpoint returning API information"""
    return {
        "name": settings.PROJECT_NAME,
        "version": "1.0.0",
        "status": "active"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "database": "connected"
    }

if __name__ == "__main__":
    try:
        logger.info("Starting application server")
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=settings.SERVER_PORT,
            reload=True,
            access_log=True
        )
    except Exception as e:
        logger.error(f"Error starting server: {str(e)}")
        raise