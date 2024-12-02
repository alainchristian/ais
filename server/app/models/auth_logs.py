from sqlalchemy import Column, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class AuthLog(Base):
    """
    Model for tracking authentication events and security-related activities.
    This model stores detailed information about login attempts, token operations,
    and other security events.
    """
    
    __tablename__ = 'auth_logs'

    # Basic fields
    id = Column(String(36), primary_key=True)
    user_id = Column(
        String(36),
        ForeignKey('users.id'),
        nullable=True,  # Nullable because failed logins might not have a user_id
        index=True
    )
    
    # Event information
    action = Column(
        String(50),
        nullable=False,
        comment="Type of authentication action (e.g., LOGIN_SUCCESS, LOGIN_FAILED)"
    )
    status = Column(
        String(50),
        nullable=False,
        comment="Outcome status of the authentication attempt"
    )
    
    # Context information
    ip_address = Column(
        String(45),  # Accommodates both IPv4 and IPv6 addresses
        nullable=True,
        comment="IP address of the client making the authentication attempt"
    )
    user_agent = Column(
        Text,
        nullable=True,
        comment="User agent string from the client's browser/application"
    )
    failure_reason = Column(
        Text,
        nullable=True,
        comment="Detailed reason for failure if the authentication attempt failed"
    )
    
    # Timestamps
    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        comment="When this log entry was created"
    )
    
    # Relationship to User model
    user = relationship(
        "User",
        back_populates="auth_logs",
        lazy="joined"
    )
    
    def __repr__(self) -> str:
        """String representation of the auth log entry"""
        timestamp = self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        return f"<AuthLog {self.action} - {self.status} - {timestamp}>"