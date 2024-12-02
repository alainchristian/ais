from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, String, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship
from app.models.base import Base
from .auth_logs import AuthLog  # Using relative import
from .associations import UserRole, UserPermission  # Import association models

class User(Base):
    """
    User model representing system users with complete authentication 
    and authorization capabilities. This model serves as the core of our
    authentication system, managing user identity, roles, and permissions.
    """
    
    __tablename__ = 'users'

    # The id column is inherited from Base, no need to redefine

    # Core user information with database constraints matching our schema
    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        doc="User's email address, serves as username for authentication"
    )
    password_hash = Column(
        String(255),
        nullable=False,
        doc="Bcrypt-hashed password for secure storage"
    )
    first_name = Column(
        String(100),
        nullable=False,
        doc="User's first name"
    )
    last_name = Column(
        String(100),
        nullable=False,
        doc="User's last name"
    )

    # Status and profile fields with proper ENUM constraints
    status = Column(
        Enum('active', 'inactive', 'suspended', name='user_status'),
        default='active',
        nullable=False,
        doc="User account status controlling access"
    )
    gender = Column(
        Enum('male', 'female', 'other', name='user_gender'),
        nullable=True,
        doc="Optional gender information"
    )
    phone = Column(
        String(50),
        nullable=True,
        doc="Optional contact phone number"
    )
    
    # Authentication tracking fields
    last_login_at = Column(
        DateTime,
        nullable=True,
        doc="Timestamp of the user's last successful login"
    )
    password_changed_at = Column(
        DateTime,
        nullable=True,
        doc="Timestamp of the user's last password change"
    )
    
    # Relationship definitions with proper back_populates and cascade settings
    user_roles = relationship(
        "UserRole",
        back_populates="user",
        cascade="all, delete-orphan",
        doc="Direct relationship to role assignments"
    )
    
    user_permissions = relationship(
        "UserPermission",
        back_populates="user",
        cascade="all, delete-orphan",
        doc="Direct relationship to permission assignments"
    )
    
    # Role relationship through the association table
    roles = relationship(
        "Role",
        secondary="user_roles",
        primaryjoin="and_(User.id == user_roles.c.user_id, "
                   "user_roles.c.deleted_at.is_(None), "
                   "user_roles.c.is_active.is_(True))",
        secondaryjoin="and_(Role.id == user_roles.c.role_id, "
                     "Role.deleted_at.is_(None))",
        viewonly=True,
        doc="Active roles assigned to this user"
    )
    
    # Permission relationship through the association table
    permissions = relationship(
        "Permission",
        secondary="user_permissions",
        primaryjoin="and_(User.id == user_permissions.c.user_id, "
                   "user_permissions.c.deleted_at.is_(None), "
                   "user_permissions.c.is_granted.is_(True))",
        secondaryjoin="and_(Permission.id == user_permissions.c.permission_id, "
                     "Permission.deleted_at.is_(None))",
        viewonly=True,
        doc="Active permissions directly assigned to this user"
    )
    
    # Security audit relationship
    auth_logs = relationship(
        "AuthLog",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
        doc="Authentication attempt logs for this user"
    )
    
    @property
    def is_active(self) -> bool:
        """
        Check if the user account is active and available for authentication.
        Returns False if the account is inactive, suspended, or soft-deleted.
        """
        return self.status == 'active' and not self.is_deleted
    
    @property
    def full_name(self) -> str:
        """
        Construct and return the user's full name by combining first and last names.
        """
        return f"{self.first_name} {self.last_name}"
    
    def get_all_permissions(self) -> List[str]:
        """
        Get a complete list of permission names from both direct assignments
        and inherited role permissions.
        
        Returns:
            List[str]: List of unique permission names
        """
        # Get directly assigned permissions
        direct_permissions = {p.name for p in self.permissions}
        
        # Get permissions from roles
        role_permissions = {
            p.name
            for role in self.roles
            for p in role.permissions
        }
        
        # Combine and return unique permissions
        return sorted(direct_permissions | role_permissions)
    
    def has_permission(self, permission_name: str) -> bool:
        """
        Check if the user has a specific permission through either
        direct assignment or role inheritance.
        
        Args:
            permission_name: The name of the permission to check
            
        Returns:
            bool: True if the user has the permission, False otherwise
        """
        # First check if user is active
        if not self.is_active:
            return False
            
        # Check direct permissions
        if any(p.name == permission_name for p in self.permissions):
            return True
        
        # Check role-based permissions
        return any(
            p.name == permission_name
            for role in self.roles
            for p in role.permissions
        )
    
    def get_security_log(self, limit: int = 10) -> List[AuthLog]:
        """
        Retrieve recent security events for this user, ordered by most recent first.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List[AuthLog]: List of authentication log entries
        """
        return self.auth_logs.order_by(AuthLog.created_at.desc()).limit(limit).all()
    
    def __str__(self) -> str:
        """String representation showing user's identity"""
        return f"{self.full_name} ({self.email})"
    
    def __repr__(self) -> str:
        """Detailed representation including key state information"""
        return f"<User {self.id}: {self.email} - {self.status}>"