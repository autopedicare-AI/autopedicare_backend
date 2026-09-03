from pydantic import BaseModel, Field
from uuid import UUID
from app.onboarding.models import RequestedAccountType, OnboardingStatus


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class RevokeTokenRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class GoogleAuthRequest(BaseModel):
    id_token: str
    requested_type: RequestedAccountType


class AppleAuthRequest(BaseModel):
    identity_token: str
    requested_type: RequestedAccountType


class AuthenticatedUserResponse(BaseModel):
    id: UUID
    email: str | None
    is_new_user: bool

class OnboardingResponse(BaseModel):
    requested_type: RequestedAccountType
    status: OnboardingStatus
    assigned_role: str | None

class AuthResponse(BaseModel):
    user: AuthenticatedUserResponse
    onboarding: OnboardingResponse | None
    tokens: TokenResponse
