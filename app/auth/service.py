import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import UserLoginHistory
from app.auth.security import create_token_pair
from app.users.models import AuthProvider, User
from app.onboarding.models import OnboardingRequest, RequestedAccountType
from app.onboarding.services import get_or_create_onboarding_request, process_onboarding

logger = logging.getLogger(__name__)


async def get_user_by_provider(
    db: AsyncSession,
    provider: AuthProvider,
    provider_id: str,
) -> User | None:

    result = await db.execute(
        select(User).where(
            User.provider == provider,
            User.provider_id == provider_id,
        )
    )

    return result.scalar_one_or_none()


async def create_user(
    db: AsyncSession,
    provider: AuthProvider,
    provider_id: str,
    email: str | None,
    is_verified: bool,
) -> User:

    user = User(
        provider=provider,
        provider_id=provider_id,
        email=email,
        is_verified=is_verified,
    )

    db.add(user)

    await db.flush()
    await db.refresh(user)

    logger.info(
        "New user created",
        extra={
            "user_id": str(user.id),
            "provider": provider.value,
        },
    )

    return user


async def authenticate_with_provider(
    session: AsyncSession,
    provider: AuthProvider,
    provider_id: str,
    email: str | None,
    is_verified: bool,
    requested_type: RequestedAccountType,
    context,
) -> tuple[User, OnboardingRequest, dict, bool]:

    try:
        user = await get_user_by_provider(
            db=session,
            provider=provider,
            provider_id=provider_id,
        )

        is_new_user = False

        if user is None:
            user = await create_user(
                db=session,
                provider=provider,
                provider_id=provider_id,
                email=email,
                is_verified=is_verified,
            )

            is_new_user = True

        else:
            logger.info(
                "Existing user authenticated",
                extra={
                    "user_id": str(user.id),
                    "provider": provider.value,
                },
            )

        onboarding = await get_or_create_onboarding_request(
            session=session,
            user_id=user.id,
            requested_type=requested_type,
        )
        
        onboarding = await process_onboarding(
            session=session,
            onboarding=onboarding,
        )

        login_history = UserLoginHistory(
            user_id=user.id,
            ip_address=context.ip,
            device=context.device,
            os=context.os,
            browser=context.browser,
            user_agent=context.user_agent,
            country=context.location.country,
            state=context.location.state,
            city=context.location.city,
            latitude=context.location.latitude,
            longitude=context.location.longitude,
            isp=context.location.isp,
            provider=provider,
            request_id=context.request_id,
            logged_in_at=context.timestamp,
        )

        session.add(login_history)

        tokens = await create_token_pair(
            session=session,
            user_id=user.id,
        )

        await session.commit()

        logger.info(
            "User authenticated successfully",
            extra={
                "user_id": str(user.id),
                "provider": provider.value,
            },
        )

        return user, onboarding, tokens, is_new_user

    except Exception:
        await session.rollback()

        logger.exception(
            "Authentication failed",
            extra={
                "provider": provider.value,
                "event": "auth_failed",
            },
        )

        raise