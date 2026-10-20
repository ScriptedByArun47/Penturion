"""Pydantic schemas for authorization requests."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


AuthorizationStatus = Literal["pending", "approved", "rejected"]


class AuthorizationRequestCreate(BaseModel):
    target_id: str = Field(min_length=36, max_length=36)

    evidence_reference: str = Field(
        min_length=1,
        max_length=500,
    )

    requested_scope: str = Field(
        min_length=1,
        max_length=10000,
    )

    requested_by: str = Field(
        min_length=1,
        max_length=100,
    )

    @field_validator(
        "target_id",
        "evidence_reference",
        "requested_scope",
        "requested_by",
    )
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("This field cannot be empty")

        return value


class AuthorizationReview(BaseModel):
    status: Literal["approved", "rejected"]

    reviewed_by: str = Field(
        min_length=1,
        max_length=100,
    )

    review_reason: str = Field(
        min_length=1,
        max_length=5000,
    )

    @field_validator("reviewed_by", "review_reason")
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("This field cannot be empty")

        return value


class AuthorizationRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_id: str
    status: AuthorizationStatus
    evidence_reference: str
    requested_scope: str
    requested_by: str
    reviewed_by: str | None
    review_reason: str | None
    reviewed_at: datetime | None
    created_at: datetime