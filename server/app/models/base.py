from datetime import datetime
from typing import Optional
from sqlalchemy import Column, String, DateTime, func
from sqlalchemy.orm import declarative_base, declared_attr
from uuid import uuid4

class CustomBase:
    """Base class for all models providing common fields and functionality"""
    
    @declared_attr
    def __tablename__(cls):
        """Generate tablename automatically based on class name"""
        return cls.__name__.lower()

    # Primary key with UUID
    id = Column(String(36), primary_key=True, index=True, default=lambda: str(uuid4()))
    
    # Audit timestamps
    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        server_default=func.now(),
        comment="Timestamp when the record was created"
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=func.now(),
        server_onupdate=func.now(),
        comment="Timestamp when the record was last updated"
    )
    deleted_at = Column(
        DateTime,
        nullable=True,
        comment="Timestamp when the record was soft deleted"
    )
    
    # Audit user references
    created_by = Column(
        String(36),
        nullable=True,
        comment="ID of the user who created this record"
    )
    updated_by = Column(
        String(36),
        nullable=True,
        comment="ID of the user who last updated this record"
    )
    deleted_by = Column(
        String(36),
        nullable=True,
        comment="ID of the user who deleted this record"
    )

    def soft_delete(self, deleted_by: Optional[str] = None) -> None:
        """Soft delete the record by setting deleted_at timestamp"""
        self.deleted_at = datetime.utcnow()
        if deleted_by:
            self.deleted_by = deleted_by

    @property
    def is_deleted(self) -> bool:
        """Check if the record has been soft deleted"""
        return self.deleted_at is not None

Base = declarative_base(cls=CustomBase)