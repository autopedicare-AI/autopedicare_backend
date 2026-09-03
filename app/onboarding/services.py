from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.onboarding.models import (
    OnboardingRequest,
    OnboardingStatus,
    RequestedAccountType,
)
from app.rbac.models import Role
from app.rbac.service import assign_role_to_user, get_role_by_name


async def get_onboarding_request(
    session: AsyncSession,
    user_id,
) -> OnboardingRequest | None:

    result = await session.execute(
        select(OnboardingRequest).where(
            OnboardingRequest.user_id == user_id
        )
    )

    return result.scalar_one_or_none()


async def create_onboarding_request(
    session: AsyncSession,
    user_id,
    requested_type: RequestedAccountType,
) -> OnboardingRequest:

    onboarding_request = OnboardingRequest(
        user_id=user_id,
        requested_type=requested_type,
        status=OnboardingStatus.PENDING,
    )

    session.add(onboarding_request)

    await session.flush()

    return onboarding_request


async def get_or_create_onboarding_request(
    session: AsyncSession,
    user_id,
    requested_type: RequestedAccountType,
) -> OnboardingRequest:

    onboarding_request = await get_onboarding_request(
        session=session,
        user_id=user_id,
    )

    if onboarding_request is not None:
        return onboarding_request

    return await create_onboarding_request(
        session=session,
        user_id=user_id,
        requested_type=requested_type,
    )


async def process_onboarding(
    session: AsyncSession,
    onboarding: OnboardingRequest,
) -> OnboardingRequest:

    if onboarding.requested_type == RequestedAccountType.CAR_OWNER:

        role = await get_role_by_name(
            session=session,
            role_name="car_owner",
        )

        if role is None:
            raise ValueError(
                "Car owner role has not been configured."
            )

        if onboarding.assigned_role_id is None or onboarding.assigned_role_id != role.id:
            await assign_role_to_user(
                db=session,
                user_id=onboarding.user_id,
                role_id=role.id,
                assigned_by=None,
            )
            onboarding.assigned_role_id = role.id

        onboarding.status = OnboardingStatus.APPROVED
        await session.flush()

    elif onboarding.requested_type == RequestedAccountType.VENDOR:

        # Vendor accounts require admin review.
        # No role is assigned at this stage.
        onboarding.status = OnboardingStatus.PENDING

        await session.flush()

    return onboarding