import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

from enum import Enum as PyEnum

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.auth.models import UserLoginHistory
    from app.onboarding.models import OnboardingRequest
    from app.rbac.models import UserRole
    from app.vehicles.models import Vehicle

class AuthProvider(str, PyEnum):
    GOOGLE = "google"
    APPLE = "apple"


class UserStatus(str, PyEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    provider: Mapped[AuthProvider] = mapped_column(
        Enum(AuthProvider, name="auth_provider"), nullable=False
    )
    provider_id: Mapped[str] = mapped_column(String(255), nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status"), default=UserStatus.ACTIVE, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    login_history: Mapped[list["UserLoginHistory"]] = relationship(
        "UserLoginHistory",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    
    onboarding_requests: Mapped[list["OnboardingRequest"]] = relationship(
        "OnboardingRequest",
        foreign_keys="OnboardingRequest.user_id",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    
    user_roles: Mapped[list["UserRole"]] = relationship(
        "UserRole",
        foreign_keys="UserRole.user_id",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    
    vehicles: Mapped[list["Vehicle"]] = relationship(
        "Vehicle",
        back_populates="owner",
        cascade="all, delete-orphan",
    )