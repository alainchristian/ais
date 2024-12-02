from datetime import datetime
from typing import Optional, List, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from fastapi import HTTPException, status
import logging
from passlib.context import CryptContext
from uuid import uuid4

from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission
from app.models.associations import UserRole, UserPermission
from app.schemas.user import UserCreate, UserUpdate

# Configure logging
logger = logging.getLogger(__name__)

# Configure password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_user_password(user: User, password: str) -> bool:
    """
    Verify if the provided password matches the user's hashed password.
    """
    try:
        return pwd_context.verify(password, user.password_hash)
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return False

def get_password_hash(password: str) -> str:
    """
    Generate a hashed version of the password.
    """
    return pwd_context.hash(password)

def get_user(db: Session, user_id: str) -> Optional[User]:
    """
    Get user by ID.
    """
    return db.query(User).filter(
        and_(User.id == user_id, User.deleted_at.is_(None))
    ).first()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """
    Get user by email address.
    """
    try:
        return db.query(User).filter(
            and_(User.email == email, User.deleted_at.is_(None))
        ).first()
    except Exception as e:
        logger.error(f"Error retrieving user by email: {str(e)}")
        return None

def get_users(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    search: Optional[str] = None
) -> List[User]:
    """
    Get list of users with optional search and pagination.
    """
    query = db.query(User).filter(User.deleted_at.is_(None))
    
    if search:
        search_filter = or_(
            User.email.ilike(f"%{search}%"),
            User.first_name.ilike(f"%{search}%"),
            User.last_name.ilike(f"%{search}%")
        )
        query = query.filter(search_filter)
    
    return query.offset(skip).limit(limit).all()

def create_user(
    db: Session,
    user_create: UserCreate,
    created_by: Optional[str] = None
) -> User:
    """
    Create a new user.
    """
    try:
        if get_user_by_email(db, user_create.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        user_data = user_create.model_dump(exclude={'password'})
        user = User(
            **user_data,
            id=str(uuid4()),
            password_hash=get_password_hash(user_create.password),
            created_by=created_by
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create user"
        )

def update_user(
    db: Session,
    user: User,
    user_update: UserUpdate,
    updated_by: Optional[str] = None
) -> User:
    """
    Update user information.
    """
    try:
        update_data = user_update.model_dump(exclude_unset=True)
        
        for field, value in update_data.items():
            setattr(user, field, value)
        
        user.updated_by = updated_by
        user.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(user)
        return user
        
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not update user"
        )

def delete_user(
    db: Session, 
    user: User, 
    deleted_by: Optional[str] = None
) -> None:
    """
    Soft delete a user by setting the deleted_at timestamp.
    """
    try:
        user.deleted_at = datetime.utcnow()
        user.deleted_by = deleted_by
        db.commit()
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not delete user"
        )

def assign_role(
    db: Session,
    user: User,
    role_id: str,
    created_by: Optional[str] = None
) -> UserRole:
    """
    Assign a role to a user.
    """
    try:
        role = db.query(Role).filter(
            and_(Role.id == role_id, Role.deleted_at.is_(None))
        ).first()
        
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )
        
        user_role = UserRole(
            id=str(uuid4()),
            user_id=user.id,
            role_id=role_id,
            created_by=created_by
        )
        
        db.add(user_role)
        db.commit()
        db.refresh(user_role)
        return user_role
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error assigning role: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not assign role"
        )

def assign_permission(
    db: Session,
    user: User,
    permission_id: str,
    is_granted: bool = True,
    reason: Optional[str] = None,
    created_by: Optional[str] = None
) -> UserPermission:
    """
    Assign a direct permission to a user.
    """
    try:
        permission = db.query(Permission).filter(
            and_(Permission.id == permission_id, Permission.deleted_at.is_(None))
        ).first()
        
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found"
            )
        
        user_permission = UserPermission(
            id=str(uuid4()),
            user_id=user.id,
            permission_id=permission_id,
            is_granted=is_granted,
            reason=reason,
            created_by=created_by
        )
        
        db.add(user_permission)
        db.commit()
        db.refresh(user_permission)
        return user_permission
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error assigning permission: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not assign permission"
        )