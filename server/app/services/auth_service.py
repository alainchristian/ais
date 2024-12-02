from datetime import datetime
from typing import Optional, Tuple, Dict
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from uuid import uuid4
import logging

from app.models.user import User
from app.models.auth_logs import AuthLog
from app.services.user_service import get_user_by_email, verify_user_password
from app.utils.jwt import create_access_token, create_refresh_token, verify_token

# Configure logging
logger = logging.getLogger(__name__)

class AuthService:
    """
    Service class handling authentication-related operations including:
    - User authentication
    - Token management
    - Security logging
    - Session tracking
    """

    @staticmethod
    def authenticate_user(
        db: Session,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[User, Dict[str, str]]:
        """
        Authenticate a user and generate access tokens.
        
        This method performs the following steps:
        1. Validates user existence and credentials
        2. Checks user account status
        3. Updates login timestamp
        4. Generates access and refresh tokens
        5. Logs the authentication attempt
        
        Args:
            db: Database session
            email: User's email address
            password: User's password
            ip_address: Client IP address for logging
            user_agent: Client user agent for logging
        
        Returns:
            Tuple containing the authenticated user and token dictionary
            
        Raises:
            HTTPException: If authentication fails for any reason
        """
        try:
            # Log authentication attempt
            logger.info(f"Authentication attempt for email: {email}")
            
            # Get user by email
            user = get_user_by_email(db, email)
            if not user:
                logger.warning(f"Login failed: User not found - {email}")
                AuthService._log_auth_attempt(
                    db, 
                    None, 
                    "LOGIN_FAILED",
                    "User not found", 
                    ip_address, 
                    user_agent
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect email or password"
                )
            
            # Verify password with enhanced error handling
            try:
                if not verify_user_password(user, password):
                    logger.warning(f"Login failed: Invalid password for user {email}")
                    AuthService._log_auth_attempt(
                        db,
                        user.id,
                        "LOGIN_FAILED",
                        "Invalid password",
                        ip_address,
                        user_agent
                    )
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Incorrect email or password"
                    )
            except Exception as e:
                logger.error(f"Password verification error: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Authentication service error"
                )
            
            # Verify user status
            if not user.is_active:
                logger.warning(f"Login failed: Inactive user - {email} - Status: {user.status}")
                AuthService._log_auth_attempt(
                    db,
                    user.id,
                    "LOGIN_FAILED",
                    f"Inactive user - Status: {user.status}",
                    ip_address,
                    user_agent
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Account is not active"
                )
            
            # Update last login timestamp
            user.last_login_at = datetime.utcnow()
            db.commit()
            
            # Generate tokens
            token_data = {
                "sub": user.email,
                "user_id": str(user.id),
                "roles": [role.name for role in user.roles]
            }
            tokens = {
                "access_token": create_access_token(data=token_data),
                "refresh_token": create_refresh_token(data=token_data),
                "token_type": "bearer"
            }
            
            # Log successful login
            logger.info(f"Successful login for user: {email}")
            AuthService._log_auth_attempt(
                db,
                user.id,
                "LOGIN_SUCCESS",
                None,
                ip_address,
                user_agent
            )
            
            return user, tokens
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected authentication error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred during authentication"
            )

    @staticmethod
    def refresh_token(
        db: Session,
        refresh_token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate new access token using refresh token.
        
        Args:
            db: Database session
            refresh_token: Valid refresh token
            ip_address: Client IP address for logging
            user_agent: Client user agent for logging
            
        Returns:
            Dictionary containing new access token
            
        Raises:
            HTTPException: If refresh token is invalid or expired
        """
        try:
            # Verify refresh token and get user
            token_data = verify_token(refresh_token)
            email = token_data.get("sub")
            
            if not email:
                logger.warning("Token refresh failed: No email in token payload")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )
            
            user = get_user_by_email(db, email)
            if not user or not user.is_active:
                logger.warning(f"Token refresh failed: Invalid or inactive user - {email}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )
            
            # Generate new access token
            new_token_data = {
                "sub": user.email,
                "user_id": str(user.id),
                "roles": [role.name for role in user.roles]
            }
            new_access_token = create_access_token(data=new_token_data)
            
            # Log token refresh
            logger.info(f"Token refresh successful for user: {email}")
            AuthService._log_auth_attempt(
                db,
                user.id,
                "TOKEN_REFRESH",
                None,
                ip_address,
                user_agent
            )
            
            return {
                "access_token": new_access_token,
                "token_type": "bearer"
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

    @staticmethod
    def _log_auth_attempt(
        db: Session,
        user_id: Optional[str],
        action: str,
        failure_reason: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> None:
        """
        Log authentication attempts for security auditing.
        
        Args:
            db: Database session
            user_id: ID of the user attempting authentication
            action: Type of authentication action
            failure_reason: Reason for failure if applicable
            ip_address: Client IP address
            user_agent: Client user agent
        """
        try:
            auth_log = AuthLog(
                id=str(uuid4()),
                user_id=user_id,
                action=action,
                status="FAILED" if failure_reason else "SUCCESS",
                failure_reason=failure_reason,
                ip_address=ip_address,
                user_agent=user_agent
            )
            db.add(auth_log)
            db.commit()
        except Exception as e:
            logger.error(f"Error logging authentication attempt: {str(e)}")
            # Don't raise the exception - we don't want logging failures to
            # affect the authentication process