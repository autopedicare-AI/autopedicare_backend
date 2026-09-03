import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import RefreshToken
from app.config import settings

logger = logging.getLogger(__name__)

REFRESH_TOKEN_EXPIRE_DAYS = 30
REFRESH_TOKEN_TYPE = "refresh"


def create_access_token(
    user_id: uuid.UUID,
) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)

    expires_at = now + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "type": "access",
        "iat": now,
        "exp": expires_at,
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    return token, expires_at


def create_refresh_token(
    user_id: uuid.UUID,
    token_family_id: uuid.UUID,
) -> tuple[str, str, datetime]:

    now = datetime.now(timezone.utc)

    expires_at = now + timedelta(
        days=REFRESH_TOKEN_EXPIRE_DAYS
    )

    jti = str(uuid.uuid4())

    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "iat": now,
        "exp": expires_at,
        "jti": jti,
        "family_id": str(token_family_id),
    }

    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    return token, jti, expires_at


def decode_token(token: str) -> dict:
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
    )


def hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


async def create_token_pair(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> dict:
    token_family_id = uuid.uuid4()

    access_token, access_expires_at = create_access_token(user_id=user_id)

    (
        refresh_token,
        refresh_jti,
        refresh_expires_at,
    ) = create_refresh_token(
        user_id=user_id,
        token_family_id=token_family_id,
    )

    refresh_token_record = RefreshToken(
        user_id=user_id,
        jti=refresh_jti,
        token_hash=hash_token(refresh_token),
        token_family_id=token_family_id,
        expires_at=refresh_expires_at,
    )

    session.add(refresh_token_record)

    await session.flush()

    logger.info(
        "Token pair created",
        extra={
            "user_id": str(user_id),
            "token_family_id": str(token_family_id),
        },
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "access_token_expires_at": access_expires_at,
        "refresh_token_expires_at": refresh_expires_at,
    }


async def rotate_refresh_token(
    session: AsyncSession,
    refresh_token: str,
) -> dict:

    try:
        payload = decode_token(refresh_token)
    except Exception:
        logger.warning(
            "Refresh token validation failed",
            extra={"event": "refresh_token_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    if payload.get("type") != REFRESH_TOKEN_TYPE:
        logger.warning(
            "Refresh token had invalid type",
            extra={"event": "refresh_token_type_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type.",
        )

    user_id = payload.get("sub")
    jti = payload.get("jti")
    family_id = payload.get("family_id")

    if not user_id or not jti or not family_id:
        logger.warning(
            "Refresh token payload malformed",
            extra={"event": "refresh_token_payload_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token payload.",
        )

    result = await session.execute(select(RefreshToken).where(RefreshToken.jti == jti))

    stored_token = result.scalar_one_or_none()

    if stored_token is None:
        logger.warning(
            "Refresh token not found in store",
            extra={"event": "refresh_token_missing"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    incoming_hash = hash_token(refresh_token)

    if stored_token.token_hash != incoming_hash:
        logger.warning(
            "Refresh token does not match stored hash",
            extra={
                "user_id": str(user_id),
                "token_family_id": str(stored_token.token_family_id),
                "event": "refresh_token_mismatch",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    if stored_token.revoked_at is not None:
        logger.warning(
            "Refresh token reuse detected",
            extra={
                "user_id": str(user_id),
                "token_family_id": str(stored_token.token_family_id),
                "event": "refresh_token_reuse",
            },
        )

        await revoke_token_family(
            session=session,
            token_family_id=stored_token.token_family_id,
        )

        await session.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token reuse detected. Session has been revoked.",
        )

    now = datetime.now(timezone.utc)

    if stored_token.expires_at <= now:
        stored_token.revoked_at = now
        await session.commit()
        logger.warning(
            "Refresh token expired",
            extra={
                "user_id": str(user_id),
                "token_family_id": str(stored_token.token_family_id),
                "event": "refresh_token_expired",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired.",
        )

    if str(stored_token.token_family_id) != family_id:
        logger.warning(
            "Refresh token family mismatch",
            extra={
                "user_id": str(user_id),
                "token_family_id": str(stored_token.token_family_id),
                "event": "refresh_token_family_mismatch",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token family.",
        )

    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        logger.warning(
            "Invalid user ID in refresh token",
            extra={"event": "refresh_token_user_id_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID in token.",
        )

    (
        new_access_token,
        new_access_expires_at,
    ) = create_access_token(user_id=user_uuid)

    (
        new_refresh_token,
        new_refresh_jti,
        new_refresh_expires_at,
    ) = create_refresh_token(
        user_id=user_uuid,
        token_family_id=stored_token.token_family_id,
    )

    new_refresh_record = RefreshToken(
        user_id=user_uuid,
        jti=new_refresh_jti,
        token_hash=hash_token(new_refresh_token),
        token_family_id=stored_token.token_family_id,
        expires_at=new_refresh_expires_at,
    )

    session.add(new_refresh_record)

    await session.flush()

    stored_token.revoked_at = now
    stored_token.replaced_by = new_refresh_record.id

    await session.commit()

    logger.info(
        "Refresh token rotated successfully",
        extra={
            "user_id": str(user_uuid),
            "token_family_id": str(stored_token.token_family_id),
        },
    )

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "access_token_expires_at": new_access_expires_at,
        "refresh_token_expires_at": new_refresh_expires_at,
    }


async def revoke_refresh_token(
    session: AsyncSession,
    refresh_token: str,
) -> None:

    try:
        payload = decode_token(refresh_token)
    except Exception:
        logger.warning(
            "Refresh token revoke failed due to invalid token",
            extra={"event": "refresh_token_revoke_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    if payload.get("type") != REFRESH_TOKEN_TYPE:
        logger.warning(
            "Refresh token revoke received invalid token type",
            extra={"event": "refresh_token_revoke_type_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type.",
        )

    jti = payload.get("jti")

    if not jti:
        logger.warning(
            "Refresh token revoke payload malformed",
            extra={"event": "refresh_token_revoke_payload_invalid"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token payload.",
        )

    result = await session.execute(select(RefreshToken).where(RefreshToken.jti == jti))

    stored_token = result.scalar_one_or_none()

    if stored_token is None:
        logger.warning(
            "Refresh token revoke not found",
            extra={"event": "refresh_token_revoke_missing"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    if stored_token.token_hash != hash_token(refresh_token):
        logger.warning(
            "Refresh token revoke hash mismatch",
            extra={
                "user_id": str(stored_token.user_id),
                "token_family_id": str(stored_token.token_family_id),
                "event": "refresh_token_revoke_mismatch",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    if stored_token.revoked_at is None:
        stored_token.revoked_at = datetime.now(timezone.utc)
        await session.commit()
        logger.info(
            "Refresh token revoked",
            extra={
                "user_id": str(stored_token.user_id),
                "token_family_id": str(stored_token.token_family_id),
            },
        )


async def revoke_token_family(
    session: AsyncSession,
    token_family_id: uuid.UUID,
) -> None:

    now = datetime.now(timezone.utc)

    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.token_family_id == token_family_id,
            RefreshToken.revoked_at.is_(None),
        )
    )

    tokens = result.scalars().all()

    for token in tokens:
        token.revoked_at = now

    logger.warning(
        "Refresh token family revoked",
        extra={
            "token_family_id": str(token_family_id),
            "event": "refresh_token_family_revoked",
        },
    )