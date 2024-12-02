from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.auth_service import AuthService
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    Token,
    RefreshTokenRequest
)
from app.core.security import get_current_user
from app.models.user import User

router = APIRouter()

@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
) -> Any:
    """
    Authenticate user and return tokens.
    
    This endpoint:
    1. Validates user credentials
    2. Creates access and refresh tokens
    3. Logs the authentication attempt
    4. Returns tokens and basic user info
    """
    # Get client info for logging
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    # Authenticate user
    try:
        user, tokens = AuthService.authenticate_user(
            db=db,
            email=login_data.email,
            password=login_data.password,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Prepare response
        return LoginResponse(
            tokens=Token(**tokens),
            user={
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "status": user.status
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your request"
        )

@router.post("/refresh-token", response_model=Token)
async def refresh_token(
    request: Request,
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
) -> Any:
    """
    Refresh access token using a valid refresh token.
    
    This endpoint:
    1. Validates the refresh token
    2. Creates a new access token
    3. Logs the token refresh
    4. Returns the new access token
    """
    try:
        tokens = AuthService.refresh_token(
            db=db,
            refresh_token=refresh_data.refresh_token,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        return Token(**tokens)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while refreshing the token"
        )

@router.post("/oauth/token", response_model=Token)
async def oauth_login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
) -> Any:
    """
    OAuth2 compatible token login, used for Swagger UI and OAuth clients.
    """
    user, tokens = AuthService.authenticate_user(
        db=db,
        email=form_data.username,  # OAuth2 uses username field for email
        password=form_data.password,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    return Token(**tokens)

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> dict:
    """
    Logout user (can be expanded to handle token revocation if needed).
    
    Currently:
    1. Logs the logout event
    2. Returns success message
    Note: Client should discard tokens on their end
    """
    # Log the logout
    AuthService._log_auth_attempt(
        db=db,
        user_id=current_user.id,
        action="LOGOUT",
        failure_reason=None,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=dict)
async def read_users_me(
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get current user information.
    Requires a valid access token.
    """
    return {
        "id": current_user.id,
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "status": current_user.status
    }