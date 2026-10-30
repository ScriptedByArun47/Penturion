"""Pydantic schemas for scan management."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    """Request to create a scan for an authorized target."""

    target_id: str = Field(min_length=1, max_length=36)
    authorization_request_id: str = Field(min_length=36, max_length=36)
    scan_type: Literal["web"] = "web"


class ScanResponse(BaseModel):
    """Public scan details returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    target_id: str
    requested_by: str
    status: str
    scan_type: str
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None