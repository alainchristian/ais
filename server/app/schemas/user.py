from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field
from uuid import UUID

class UserBase(BaseModel):
    """Base schema for user data"""
    email: EmailStr
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    gender: Optional[str] = Field(None, pattern='^(male|female|other)$')
    phone: Optional[str] = None
    status: Optional[str] = Field('active', pattern='^(active|inactive|suspended)$')

class UserCreate(UserBase):
    """Schema for creating a new user"""
    password: str = Field(..., min_length=8)

class UserUpdate(BaseModel):
    """Schema for updating user information"""
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    gender: Optional[str] = Field(None, pattern='^(male|female|other)$')
    phone: Optional[str] = None
    status: Optional[str] = Field(None, pattern='^(active|inactive|suspended)$')

class UserInDBBase(UserBase):
    """Base schema for user data from database"""
    id: UUID
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class UserInDB(UserInDBBase):
    """Complete user schema including password hash (for internal use)"""
    password_hash: str

class UserResponse(UserInDBBase):
    """Schema for user responses, excluding sensitive data"""
    roles: List[str] = []
    permissions: List[str] = []

    class Config:
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "user@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "status": "active",
                "roles": ["Admin"],
                "permissions": ["user.view", "user.edit"]
            }
        }