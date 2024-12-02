from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class Token(BaseModel):
    """
    Schema for authentication tokens returned to the client.
    Includes both access and refresh tokens along with their type.
    """
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str

class TokenData(BaseModel):
    """
    Schema for decoded token payload data.
    Used internally for token verification and user identification.
    """
    email: Optional[str] = None
    user_id: Optional[str] = None

class LoginRequest(BaseModel):
    """
    Schema for login request data.
    Validates email format and ensures password meets minimum requirements.
    """
    email: EmailStr
    password: str = Field(..., min_length=8)
    
class RefreshTokenRequest(BaseModel):
    """
    Schema for token refresh requests.
    Used when the client wants to obtain a new access token using a refresh token.
    """
    refresh_token: str

class LoginResponse(BaseModel):
    """
    Schema for successful login response.
    Includes tokens and basic user information.
    """
    tokens: Token
    user: dict  # Basic user info like id, email, name
    
    class Config:
        json_schema_extra = {
            "example": {
                "tokens": {
                    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
                    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
                    "token_type": "bearer"
                },
                "user": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "email": "user@example.com",
                    "first_name": "John",
                    "last_name": "Doe"
                }
            }
        }