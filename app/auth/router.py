import logging
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.google import verify_google_token
from app.auth.schemas import (
    AuthResponse,
    AuthenticatedUserResponse,
    GoogleAuthRequest,
    OnboardingResponse,
    RefreshTokenRequest,
    RevokeTokenRequest,
    TokenResponse,
)
from app.auth.security import (
    revoke_refresh_token,
    rotate_refresh_token,
)
from app.auth.service import authenticate_with_provider
from app.database import get_db
from app.rbac.models import Role
from app.users.models import AuthProvider, User

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/refresh",
    response_model=TokenResponse,
)
async def refresh_tokens(
    payload: RefreshTokenRequest,
    session: AsyncSession = Depends(get_db),
):
    return await rotate_refresh_token(
        session=session,
        refresh_token=payload.refresh_token,
    )


@router.post(
    "/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_tokens(
    payload: RevokeTokenRequest,
    session: AsyncSession = Depends(get_db),
):
    await revoke_refresh_token(
        session=session,
        refresh_token=payload.refresh_token,
    )


@router.post(
    "/google",
    response_model=AuthResponse,
)
async def google_auth(
    payload: GoogleAuthRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):

    context = getattr(request.state, "context", None)

    if context is None:
        logger.error(
            "Request context unavailable for Google authentication",
            extra={"event": "auth_context_missing"},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User context is unavailable.",
        )

    try:
        google_user = await verify_google_token(payload.id_token)
    except ValueError:
        logger.warning(
            "Invalid Google authentication token",
            extra={"provider": "google", "event": "google_token_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google authentication token.",
        )

    user, onboarding, tokens, is_new_user = await authenticate_with_provider(
        session=db,
        provider=AuthProvider.GOOGLE,
        provider_id=google_user["provider_id"],
        email=google_user.get("email"),
        is_verified=google_user["email_verified"],
        requested_type=payload.requested_type,
        context=context,
    )

    authenticated_user = cast(User, user)

    assigned_role_name = None
    if onboarding.assigned_role_id is not None:
        result = await db.execute(
            select(Role.name).where(Role.id == onboarding.assigned_role_id)
        )
        assigned_role_name = result.scalar_one_or_none()

    return AuthResponse(
        user=AuthenticatedUserResponse(
            id=authenticated_user.id,
            email=authenticated_user.email,
            is_new_user=is_new_user,
        ),
        onboarding=OnboardingResponse(
            requested_type=onboarding.requested_type,
            status=onboarding.status,
            assigned_role=assigned_role_name,
        ),
        tokens=TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type=tokens["token_type"],
        ),
    )
