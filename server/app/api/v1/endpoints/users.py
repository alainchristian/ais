from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user, get_current_admin_user
from app.services.user_service import (
    create_user,
    get_user,
    get_users,
    update_user,
    delete_user,
    assign_role,
    assign_permission
)
from app.schemas.user import (
    UserCreate,
    UserUpdate,
    UserResponse,
    UserInDB
)
from app.models.user import User

# Initialize router with prefix and tags for API documentation
router = APIRouter()

@router.get("/me", response_model=UserResponse)
async def read_user_me(
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get current user information.
    This endpoint returns detailed information about the authenticated user.
    """
    return current_user

@router.get("", response_model=List[UserResponse])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    search: str = None,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
) -> Any:
    """
    Retrieve users with pagination and search capabilities.
    Only administrators can access this endpoint.
    """
    users = get_users(db, skip=skip, limit=limit, search=search)
    return users

@router.get("/{user_id}", response_model=UserResponse)
async def read_user_by_id(
    user_id: str,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
) -> Any:
    """
    Get a specific user by ID.
    Only administrators can access this endpoint.
    """
    user = get_user(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

@router.post("", response_model=UserResponse)
async def create_new_user(
    user_in: UserCreate,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
) -> Any:
    """
    Create a new user.
    Only administrators can create new users.
    """
    user = create_user(db, user_in, created_by=current_user.id)
    return user

@router.put("/{user_id}", response_model=UserResponse)
async def update_user_details(
    user_id: str,
    user_in: UserUpdate,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
) -> Any:
    """
    Update a user's information.
    Only administrators can update user information.
    """
    user = get_user(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    updated_user = update_user(db, user, user_in, updated_by=current_user.id)
    return updated_user

@router.delete("/{user_id}")
async def delete_user_by_id(
    user_id: str,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
) -> Any:
    """
    Soft delete a user.
    Only administrators can delete users.
    """
    user = get_user(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Users cannot delete their own accounts"
        )
    
    delete_user(db, user, deleted_by=current_user.id)
    return {"message": "User successfully deleted"}

@router.post("/{user_id}/roles/{role_id}")
async def assign_user_role(
    user_id: str,
    role_id: str,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
) -> Any:
    """
    Assign a role to a user.
    Only administrators can assign roles.
    """
    user = get_user(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    try:
        user_role = assign_role(
            db, 
            user, 
            role_id, 
            created_by=current_user.id
        )
        return {"message": "Role successfully assigned"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/{user_id}/permissions/{permission_id}")
async def assign_user_permission(
    user_id: str,
    permission_id: str,
    is_granted: bool = True,
    reason: str = None,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
) -> Any:
    """
    Assign a direct permission to a user.
    Only administrators can assign permissions.
    """
    user = get_user(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    try:
        user_permission = assign_permission(
            db,
            user,
            permission_id,
            is_granted=is_granted,
            reason=reason,
            created_by=current_user.id
        )
        return {"message": "Permission successfully assigned"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )