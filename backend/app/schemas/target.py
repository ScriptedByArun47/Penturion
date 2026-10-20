from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


TargetType = Literal["domain", "ip", "url"]

AuthorizationStatus = Literal[
    "pending",
    "approved",
    "rejected",
]


class TargetCreate(BaseModel):
    value: str = Field(min_length=1, max_length=253)
    target_type: TargetType
    notes: str | None = Field(default=None, max_length=5000)

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Target value cannot be empty")

        if any(character.isspace() for character in value):
            raise ValueError(
                "Target value must not contain whitespace"
            )

        return value


class TargetUpdate(BaseModel):
    value: str | None = Field(
        default=None,
        min_length=1,
        max_length=253,
    )
    notes: str | None = Field(default=None, max_length=5000)

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str | None) -> str | None:
        if value is None:
            return None

        value = value.strip()

        if not value:
            raise ValueError("Target value cannot be empty")

        if any(character.isspace() for character in value):
            raise ValueError(
                "Target value must not contain whitespace"
            )

        return value


class TargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    value: str
    target_type: str
    authorization_status: AuthorizationStatus
    notes: str | None
    created_at: datetime