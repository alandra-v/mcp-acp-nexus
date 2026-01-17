"""Error response schemas for API documentation.

These schemas are used for OpenAPI documentation and type hints.
The actual error handling is in api/errors.py.
"""

from __future__ import annotations

__all__ = [
    "ErrorDetail",
    "ErrorResponse",
    "ValidationErrorItem",
]

from typing import Any

from pydantic import BaseModel, Field


class ValidationErrorItem(BaseModel):
    """Single validation error from Pydantic.

    Attributes:
        loc: Location of the error (e.g., ["body", "name"]).
        msg: Human-readable error message.
        type: Error type identifier.
    """

    loc: list[str | int] = Field(description="Location of the error in the request")
    msg: str = Field(description="Human-readable error message")
    type: str = Field(description="Error type identifier")


class ErrorDetail(BaseModel):
    """Structured error detail.

    Attributes:
        code: Error code for programmatic handling (e.g., "APPROVAL_NOT_FOUND").
        message: Human-readable error message.
        details: Optional contextual details (varies by error type).
        validation_errors: Optional Pydantic validation errors (for 422 responses).
    """

    code: str = Field(
        description="Error code for programmatic handling",
        examples=["APPROVAL_NOT_FOUND", "AUTH_REQUIRED", "VALIDATION_ERROR"],
    )
    message: str = Field(
        description="Human-readable error message",
        examples=["Pending approval 'abc123' not found"],
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description="Optional contextual details",
        examples=[{"approval_id": "abc123"}],
    )
    validation_errors: list[ValidationErrorItem] | None = Field(
        default=None,
        description="Pydantic validation errors (for 422 responses)",
    )


class ErrorResponse(BaseModel):
    """Full error response wrapper.

    This matches FastAPI's default error response structure
    with our structured ErrorDetail.

    Attributes:
        detail: Structured error detail.
    """

    detail: ErrorDetail
