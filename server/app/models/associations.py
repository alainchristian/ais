from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from app.models.base import Base

class UserRole(Base):
    """Association model for user-role relationships with time bounds"""
    
    __tablename__ = 'user_roles'
    
    # Foreign keys with proper constraints
    user_id = Column(
        String(36),
        ForeignKey('users.id', ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    role_id = Column(
        String(36),
        ForeignKey('roles.id', ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Time bounds for role assignment
    start_date = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )
    end_date = Column(
        DateTime,
        nullable=True
    )
    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )
    
    # Define relationships
    user = relationship("User", back_populates="user_roles")
    role = relationship("Role", back_populates="role_users")
    
    # Add unique constraint
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', 'start_date', name='uk_user_role_start'),
    )

class UserPermission(Base):
    """Association model for user-permission relationships with override capabilities"""
    
    __tablename__ = 'user_permissions'
    
    # Foreign keys with proper constraints
    user_id = Column(
        String(36),
        ForeignKey('users.id', ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    permission_id = Column(
        String(36),
        ForeignKey('permissions.id', ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Permission override settings
    is_granted = Column(
        Boolean,
        nullable=False,
        default=True
    )
    start_date = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )
    end_date = Column(
        DateTime,
        nullable=True
    )
    reason = Column(
        Text,
        nullable=True
    )
    
    # Define relationships
    user = relationship("User", back_populates="user_permissions")
    permission = relationship("Permission", back_populates="permission_users")
    
    # Add unique constraint
    __table_args__ = (
        UniqueConstraint('user_id', 'permission_id', name='uk_user_permission'),
    )

class RolePermission(Base):
    """Association model for role-permission relationships"""
    
    __tablename__ = 'role_permissions'
    
    # Foreign keys with proper constraints
    role_id = Column(
        String(36),
        ForeignKey('roles.id', ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    permission_id = Column(
        String(36),
        ForeignKey('permissions.id', ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Define relationships
    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="permission_roles")
    
    # Add unique constraint
    __table_args__ = (
        UniqueConstraint('role_id', 'permission_id', name='uk_role_permission'),
    )