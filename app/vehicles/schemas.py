from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class VehicleCreate(BaseModel):
    make: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=100)
    year: int = Field(ge=1886)
    vin: str | None = Field(
        default=None,
        min_length=17,
        max_length=17,
    )
    license_plate: str | None = Field(
        default=None,
        max_length=50,
    )
    color: str | None = Field(
        default=None,
        max_length=50,
    )


class VehicleUpdate(BaseModel):
    make: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )
    model: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )
    year: int | None = Field(
        default=None,
        ge=1886,
    )
    vin: str | None = Field(
        default=None,
        min_length=17,
        max_length=17,
    )
    license_plate: str | None = Field(
        default=None,
        max_length=50,
    )
    color: str | None = Field(
        default=None,
        max_length=50,
    )


class VehicleResponse(BaseModel):
    id: UUID
    owner_id: UUID
    make: str
    model: str
    year: int
    vin: str | None
    license_plate: str | None
    color: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
