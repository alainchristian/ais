from sqlalchemy import Column, String, Boolean, Text
from sqlalchemy.orm import relationship
from app.models.base import Base
from .associations import RolePermission, UserRole

class Role(Base):
    """
    Role model representing user roles for access control.
    Roles are collections of permissions that can be assigned to users,
    making permission management more scalable and maintainable.
    """
    
    __tablename__ = 'roles'
    
    # Core role attributes
    name = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
        doc="Unique name identifying the role"
    )
    description = Column(
        Text,
        nullable=True,
        doc="Detailed description of the role's purpose and scope"
    )
    is_system = Column(
        Boolean,
        default=False,
        nullable=False,
        doc="Indicates if this is a core system role that cannot be modified"
    )
    
    # Relationship to role assignments (bidirectional)
    role_users = relationship(
        "UserRole",
        back_populates="role",
        cascade="all, delete-orphan",
        doc="Direct relationship to user assignments"
    )
    
    # Relationship to permission assignments (bidirectional)
    role_permissions = relationship(
        "RolePermission",
        back_populates="role",
        cascade="all, delete-orphan",
        doc="Direct relationship to permission assignments"
    )
    
    # Users relationship through the association table
    users = relationship(
        "User",
        secondary="user_roles",
        primaryjoin="and_(Role.id == user_roles.c.role_id, "
                   "user_roles.c.deleted_at.is_(None), "
                   "user_roles.c.is_active.is_(True))",
        secondaryjoin="and_(User.id == user_roles.c.user_id, "
                     "User.deleted_at.is_(None))",
        viewonly=True,
        doc="Users currently assigned this role"
    )
    
    # Permissions relationship through the association table
    permissions = relationship(
        "Permission",
        secondary="role_permissions",
        primaryjoin="and_(Role.id == role_permissions.c.role_id, "
                   "role_permissions.c.deleted_at.is_(None))",
        secondaryjoin="and_(Permission.id == role_permissions.c.permission_id, "
                     "Permission.deleted_at.is_(None))",
        viewonly=True,
        doc="Permissions granted by this role"
    )
    
    def has_permission(self, permission_name: str) -> bool:
        """
        Check if this role includes a specific permission.
        
        Args:
            permission_name: The name of the permission to check
            
        Returns:
            bool: True if the role includes the permission, False otherwise
        """
        return any(p.name == permission_name for p in self.permissions)
    
    def get_active_users_count(self) -> int:
        """
        Get the count of active users currently assigned this role.
        
        Returns:
            int: Number of active users with this role
        """
        return sum(1 for user in self.users if user.is_active)
    
    def __str__(self) -> str:
        """String representation showing role name"""
        return self.name
    
    def __repr__(self) -> str:
        """Detailed representation including system role status"""
        return f"<Role {self.id}: {self.name} ({'system' if self.is_system else 'custom'})>"