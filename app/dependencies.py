import logging
import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import decode_token
from app.database import get_db
from app.rbac.models import Permission, Role, RolePermission, UserRole
from app.users.models import User, UserStatus


logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validate the access token and return the authenticated user.
    """

    token = credentials.credentials

    try:
        payload = decode_token(token)
    except Exception:
        logger.warning(
            "Access token validation failed",
            extra={"event": "access_token_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        logger.warning(
            "Invalid token type used for authentication",
            extra={"event": "access_token_type_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")

    if not user_id:
        logger.warning(
            "Access token missing user ID",
            extra={"event": "access_token_subject_missing"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_uuid = uuid.UUID(user_id)
    except (ValueError, AttributeError, TypeError):
        logger.warning(
            "Invalid user ID in access token",
            extra={"event": "access_token_user_id_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID in access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(
        select(User).where(User.id == user_uuid)
    )

    user = result.scalar_one_or_none()

    if user is None:
        logger.warning(
            "Authenticated user not found",
            extra={
                "user_id": str(user_uuid),
                "event": "authenticated_user_not_found",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.status != UserStatus.ACTIVE:
        logger.warning(
            "Inactive user attempted authentication",
            extra={
                "user_id": str(user.id),
                "status": user.status.value,
                "event": "inactive_user_authentication",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not active.",
        )

    return user


def require_role(role_name: str):
    """
    Require the authenticated user to have a specific RBAC role.
    """

    async def role_checker(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:

        result = await db.execute(
            select(UserRole)
            .join(Role, UserRole.role_id == Role.id)
            .where(
                UserRole.user_id == current_user.id,
                Role.name == role_name,
            )
        )

        user_role = result.scalar_one_or_none()

        if user_role is None:
            logger.warning(
                "User attempted access without required role",
                extra={
                    "user_id": str(current_user.id),
                    "required_role": role_name,
                    "event": "role_authorization_failed",
                },
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have the required role.",
            )

        return current_user

    return role_checker


def require_permission(permission_name: str):
    """
    Require the authenticated user to have a specific RBAC permission.
    """

    async def permission_checker(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:

        result = await db.execute(
            select(Permission)
            .join(
                RolePermission,
                RolePermission.permission_id == Permission.id,
            )
            .join(
                UserRole,
                UserRole.role_id == RolePermission.role_id,
            )
            .where(
                UserRole.user_id == current_user.id,
                Permission.name == permission_name,
            )
        )

        permission = result.scalar_one_or_none()

        if permission is None:
            logger.warning(
                "User attempted access without required permission",
                extra={
                    "user_id": str(current_user.id),
                    "required_permission": permission_name,
                    "event": "permission_authorization_failed",
                },
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )

        return current_user

    return permission_checker