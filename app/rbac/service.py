from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.rbac.models import Role, UserRole


async def get_role_by_name(session: AsyncSession, role_name: str) -> Role | None:
    result = await session.execute(select(Role).where(Role.name == role_name))
    return result.scalar_one_or_none()


async def assign_role_to_user(
    db: AsyncSession,
    user_id,
    role_id,
    assigned_by=None,
) -> UserRole:

    result = await db.execute(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
        )
    )

    existing = result.scalar_one_or_none()

    if existing is not None:
        return existing

    user_role = UserRole(
        user_id=user_id,
        role_id=role_id,
        assigned_by=assigned_by,
    )

    db.add(user_role)

    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        existing = await db.scalar(
            select(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id == role_id,
            )
        )
        if existing is not None:
            return existing
        raise

    return user_role
