from sqlalchemy import Column, String, Boolean, Text
from sqlalchemy.orm import relationship
from app.models.base import Base
from .associations import RolePermission, UserPermission

class Permission(Base):
    """
    Permission model defining granular access controls within the system.
    
    Permissions represent specific actions that can be performed in the system.
    They can be assigned directly to users or granted through roles. Each permission
    belongs to a category (e.g., 'user', 'student', 'attendance') and can be
    marked as a system permission that cannot be modified by regular administrators.
    """
    
    __tablename__ = 'permissions'
    
    # Core permission attributes
    name = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        doc="Unique identifier for the permission (e.g., 'user.create')"
    )
    description = Column(
        Text,
        nullable=True,
        doc="Human-readable description of what this permission allows"
    )
    category = Column(
        String(50),
        nullable=False,
        index=True,
        doc="Grouping category for organizing permissions (e.g., 'user', 'student')"
    )
    is_system = Column(
        Boolean,
        default=False,
        nullable=False,
        doc="Indicates if this is a core system permission that cannot be modified"
    )
    
    # Direct relationship to permission assignments
    permission_users = relationship(
        "UserPermission",
        back_populates="permission",
        cascade="all, delete-orphan",
        doc="Direct user assignment records for this permission"
    )
    
    permission_roles = relationship(
        "RolePermission",
        back_populates="permission",
        cascade="all, delete-orphan",
        doc="Role assignment records for this permission"
    )
    
    # Relationship to users through the association table
    users = relationship(
        "User",
        secondary="user_permissions",
        primaryjoin="and_(Permission.id == user_permissions.c.permission_id, "
                   "user_permissions.c.deleted_at.is_(None), "
                   "user_permissions.c.is_granted.is_(True))",
        secondaryjoin="and_(User.id == user_permissions.c.user_id, "
                     "User.deleted_at.is_(None))",
        viewonly=True,
        doc="Users directly granted this permission"
    )
    
    # Relationship to roles through the association table
    roles = relationship(
        "Role",
        secondary="role_permissions",
        primaryjoin="and_(Permission.id == role_permissions.c.permission_id, "
                   "role_permissions.c.deleted_at.is_(None))",
        secondaryjoin="and_(Role.id == role_permissions.c.role_id, "
                     "Role.deleted_at.is_(None))",
        viewonly=True,
        doc="Roles that include this permission"
    )
    
    def get_user_count(self, include_roles: bool = True) -> int:
        """
        Count how many users have this permission, either directly or through roles.
        
        Args:
            include_roles: If True, includes users who have the permission through roles
            
        Returns:
            int: Number of users with this permission
        """
        # Count direct permission assignments
        direct_count = len([u for u in self.users if u.is_active])
        
        if not include_roles:
            return direct_count
            
        # Add users who have the permission through roles
        role_users = set()
        for role in self.roles:
            role_users.update(u.id for u in role.users if u.is_active)
            
        return direct_count + len(role_users)
    
    def get_users_with_permission(self, include_roles: bool = True) -> list:
        """
        Get all users who have this permission, either directly or through roles.
        
        Args:
            include_roles: If True, includes users who have the permission through roles
            
        Returns:
            list: List of User objects with this permission
        """
        # Get users with direct permission
        users_set = set(u for u in self.users if u.is_active)
        
        if include_roles:
            # Add users who have the permission through roles
            for role in self.roles:
                users_set.update(u for u in role.users if u.is_active)
        
        return sorted(users_set, key=lambda u: u.email)
    
    def __str__(self) -> str:
        """String representation showing permission name and category"""
        return f"{self.name} ({self.category})"
    
    def __repr__(self) -> str:
        """Detailed representation including system permission status"""
        return f"<Permission {self.id}: {self.name} - {self.category}>"