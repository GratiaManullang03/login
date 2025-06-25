"""
Base model untuk SQLAlchemy.
Semua model harus inherit dari BaseModel untuk mendapatkan common fields dan behavior.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from sqlalchemy import Column, DateTime, String, inspect
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import as_declarative, declared_attr
from sqlalchemy.orm import Session


@as_declarative()
class Base:
    """
    Base class untuk semua SQLAlchemy models.
    Menggunakan @as_declarative untuk membuat declarative base.
    """
    
    # Generate __tablename__ automatically dari class name
    @declared_attr
    def __tablename__(cls) -> str:
        """
        Generate table name dari class name.
        Contoh: UserSession -> user_sessions
        """
        # Convert CamelCase to snake_case
        name = cls.__name__
        # Handle acronyms dan multiple capitals
        result = []
        for i, char in enumerate(name):
            if i > 0 and char.isupper():
                # Check if previous char was lowercase or next char is lowercase
                if (name[i-1].islower() or 
                    (i < len(name) - 1 and name[i+1].islower())):
                    result.append('_')
            result.append(char.lower())
        
        # Pluralize (simple version - bisa di-improve)
        table_name = ''.join(result)
        if not table_name.endswith('s'):
            if table_name.endswith('y'):
                table_name = table_name[:-1] + 'ies'
            elif table_name.endswith(('x', 'ch', 'sh')):
                table_name += 'es'
            else:
                table_name += 's'
        
        return table_name
    
    def dict(self, exclude: Optional[set] = None) -> Dict[str, Any]:
        """
        Convert model instance to dictionary.
        
        Args:
            exclude: Set of fields to exclude
            
        Returns:
            Dictionary representation of model
        """
        exclude = exclude or set()
        
        # Get all columns
        columns = inspect(self.__class__).columns
        
        result = {}
        for column in columns:
            if column.name not in exclude:
                value = getattr(self, column.name)
                
                # Handle special types
                if isinstance(value, datetime):
                    value = value.isoformat()
                elif isinstance(value, uuid.UUID):
                    value = str(value)
                
                result[column.name] = value
        
        return result
    
    def update(self, **kwargs) -> None:
        """
        Update model instance dengan keyword arguments.
        
        Args:
            **kwargs: Fields to update
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def __repr__(self) -> str:
        """
        String representation of model instance.
        """
        class_name = self.__class__.__name__
        
        # Try to get primary key
        primary_keys = []
        for column in inspect(self.__class__).primary_key:
            value = getattr(self, column.name)
            primary_keys.append(f"{column.name}={value}")
        
        if primary_keys:
            return f"<{class_name}({', '.join(primary_keys)})>"
        else:
            return f"<{class_name}>"


class BaseModel(Base):
    """
    Abstract base model dengan common fields.
    Semua models yang perlu timestamp fields harus inherit dari ini.
    """
    __abstract__ = True
    
    # Common timestamp fields
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    
    updated_at = Column(
        DateTime(timezone=True),
        default=None,
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=True
    )
    
    @declared_attr
    def __mapper_args__(cls):
        """
        SQLAlchemy mapper arguments.
        Enable eager defaults untuk mendapatkan server-generated values.
        """
        return {
            "eager_defaults": True
        }
    
    def save(self, db: Session) -> None:
        """
        Save model instance to database.
        Helper method untuk kemudahan.
        
        Args:
            db: Database session
        """
        db.add(self)
        
    async def asave(self, db: Any) -> None:
        """
        Async save untuk AsyncSession.
        
        Args:
            db: Async database session
        """
        db.add(self)
        
    def delete(self, db: Session) -> None:
        """
        Delete model instance from database.
        
        Args:
            db: Database session
        """
        db.delete(self)
        
    async def adelete(self, db: Any) -> None:
        """
        Async delete untuk AsyncSession.
        
        Args:
            db: Async database session
        """
        await db.delete(self)
    
    def refresh(self, db: Session) -> None:
        """
        Refresh model instance from database.
        
        Args:
            db: Database session
        """
        db.refresh(self)
        
    async def arefresh(self, db: Any) -> None:
        """
        Async refresh untuk AsyncSession.
        
        Args:
            db: Async database session
        """
        await db.refresh(self)


class UUIDModel(BaseModel):
    """
    Base model dengan UUID primary key.
    Kebanyakan models akan inherit dari ini.
    """
    __abstract__ = True
    
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
        index=True
    )


class TimestampMixin:
    """
    Mixin untuk menambahkan timestamp fields.
    Alternatif untuk models yang tidak inherit dari BaseModel.
    """
    
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    
    updated_at = Column(
        DateTime(timezone=True),
        default=None,
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=True
    )


class SoftDeleteMixin:
    """
    Mixin untuk soft delete functionality.
    """
    
    deleted_at = Column(
        DateTime(timezone=True),
        default=None,
        nullable=True,
        index=True
    )
    
    @property
    def is_deleted(self) -> bool:
        """Check if record is soft deleted."""
        return self.deleted_at is not None
    
    def soft_delete(self) -> None:
        """Mark record as deleted."""
        self.deleted_at = datetime.now(timezone.utc)
    
    def restore(self) -> None:
        """Restore soft deleted record."""
        self.deleted_at = None