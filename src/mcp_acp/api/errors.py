"""Structured API error handling.

This module provides:
- ErrorCode enum with domain-grouped error codes
- APIError exception class for structured error responses
- Global exception handlers for consistent error formatting

Usage:
    from mcp_acp.api.errors import APIError, ErrorCode

    raise APIError(
        status_code=404,
        code=ErrorCode.APPROVAL_NOT_FOUND,
        message="Pending approval not found",
        details={"approval_id": "abc123"},
    )

Response format:
    {
        "detail": {
            "code": "APPROVAL_NOT_FOUND",
            "message": "Pending approval not found",
            "details": {"approval_id": "abc123"}
        }
    }
"""

from __future__ import annotations

__all__ = [
    "APIError",
    "ErrorCode",
    "api_error_handler",
    "http_exception_handler",
    "validation_error_handler",
]

from enum import Enum
from typing import Any

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class ErrorCode(str, Enum):
    """API error codes for programmatic handling.

    Codes are namespaced by domain:
    - AUTH_*: Authentication/authorization errors
    - APPROVAL_*: HITL approval errors
    - POLICY_*: Policy management errors
    - CONFIG_*: Configuration errors
    - PROXY_*: Proxy-related errors
    - LOG_*: Log access errors
    - VALIDATION_*: Input validation errors
    - INTERNAL_*: Internal server errors
    """

    # Authentication errors (401, 403)
    AUTH_REQUIRED = "AUTH_REQUIRED"
    AUTH_FORBIDDEN = "AUTH_FORBIDDEN"
    AUTH_PROVIDER_UNAVAILABLE = "AUTH_PROVIDER_UNAVAILABLE"
    AUTH_DEVICE_FLOW_FAILED = "AUTH_DEVICE_FLOW_FAILED"
    AUTH_DEVICE_FLOW_LIMIT = "AUTH_DEVICE_FLOW_LIMIT"

    # Approval errors (403, 404)
    APPROVAL_NOT_FOUND = "APPROVAL_NOT_FOUND"
    APPROVAL_UNAUTHORIZED = "APPROVAL_UNAUTHORIZED"
    CACHED_APPROVAL_NOT_FOUND = "CACHED_APPROVAL_NOT_FOUND"

    # Policy errors (400, 404, 409, 500)
    POLICY_NOT_FOUND = "POLICY_NOT_FOUND"
    POLICY_INVALID = "POLICY_INVALID"
    POLICY_RULE_NOT_FOUND = "POLICY_RULE_NOT_FOUND"
    POLICY_RULE_DUPLICATE = "POLICY_RULE_DUPLICATE"
    POLICY_RELOAD_FAILED = "POLICY_RELOAD_FAILED"

    # Config errors (400, 404, 500)
    CONFIG_NOT_FOUND = "CONFIG_NOT_FOUND"
    CONFIG_INVALID = "CONFIG_INVALID"
    CONFIG_SAVE_FAILED = "CONFIG_SAVE_FAILED"

    # Resource errors (404)
    PROXY_NOT_FOUND = "PROXY_NOT_FOUND"
    LOG_NOT_AVAILABLE = "LOG_NOT_AVAILABLE"
    NOT_FOUND = "NOT_FOUND"  # Generic 404 for unmapped exceptions

    # Conflict errors (409)
    CONFLICT = "CONFLICT"  # Generic 409 for unmapped exceptions
    PROXY_EXISTS = "PROXY_EXISTS"  # Proxy already exists

    # Proxy creation errors (400, 500)
    PROXY_INVALID = "PROXY_INVALID"  # Invalid proxy configuration
    PROXY_CREATION_FAILED = "PROXY_CREATION_FAILED"  # Failed to create proxy

    # Validation errors (400, 422)
    VALIDATION_ERROR = "VALIDATION_ERROR"

    # Internal errors (500, 501, 502, 503)
    INTERNAL_ERROR = "INTERNAL_ERROR"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class APIError(HTTPException):
    """Structured API error with error code.

    Extends HTTPException to provide consistent structured error responses
    with error codes for programmatic handling.

    Attributes:
        status_code: HTTP status code.
        code: Error code from ErrorCode enum.
        error_message: Human-readable error message.
        error_details: Optional contextual details.
        validation_errors: Optional Pydantic validation errors.
    """

    def __init__(
        self,
        status_code: int,
        code: ErrorCode,
        message: str,
        details: dict[str, Any] | None = None,
        validation_errors: list[dict[str, Any]] | None = None,
    ) -> None:
        """Initialize structured API error.

        Args:
            status_code: HTTP status code.
            code: Error code from ErrorCode enum.
            message: Human-readable error message.
            details: Optional contextual details (varies by error type).
            validation_errors: Optional Pydantic validation errors.
        """
        self.code = code
        self.error_message = message
        self.error_details = details
        self.validation_errors = validation_errors

        # Build structured detail dict
        detail: dict[str, Any] = {
            "code": code.value,
            "message": message,
        }
        if details:
            detail["details"] = details
        if validation_errors:
            detail["validation_errors"] = validation_errors

        super().__init__(status_code=status_code, detail=detail)


async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """Handle APIError exceptions with structured response.

    Args:
        request: FastAPI request object.
        exc: APIError exception instance.

    Returns:
        JSONResponse with structured error detail.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle Pydantic validation errors with structured response.

    Converts Pydantic validation errors to our structured format while
    preserving the detailed field-level error information.

    Args:
        request: FastAPI request object.
        exc: RequestValidationError from Pydantic.

    Returns:
        JSONResponse with structured error detail including validation_errors.
    """
    errors = exc.errors()
    first_error = errors[0] if errors else {}

    loc = first_error.get("loc", [])
    msg = first_error.get("msg", "Validation error")

    # Build human-readable message
    if len(errors) == 1:
        # Filter out 'body' from location path
        field_parts = [str(part) for part in loc if part != "body"]
        field_name = ".".join(field_parts)
        message = f"{field_name}: {msg}" if field_name else msg
    else:
        message = f"{len(errors)} validation errors"

    detail: dict[str, Any] = {
        "code": ErrorCode.VALIDATION_ERROR.value,
        "message": message,
        "validation_errors": [
            {
                "loc": list(e.get("loc", [])),
                "msg": e.get("msg", ""),
                "type": e.get("type", ""),
            }
            for e in errors
        ],
    }

    return JSONResponse(
        status_code=422,
        content={"detail": detail},
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handle standard HTTPException for backward compatibility.

    Wraps plain string details in structured format for consistency.
    Passes through already-structured details from APIError.

    Args:
        request: FastAPI request object.
        exc: HTTPException (Starlette or FastAPI).

    Returns:
        JSONResponse with structured error detail.
    """
    # If detail is already structured (from APIError), use as-is
    if isinstance(exc.detail, dict) and "code" in exc.detail:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    # Wrap plain string in structured format
    code = _status_to_error_code(exc.status_code)
    message = str(exc.detail) if exc.detail else f"HTTP {exc.status_code}"

    detail: dict[str, Any] = {
        "code": code.value,
        "message": message,
    }

    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": detail},
    )


def _status_to_error_code(status_code: int) -> ErrorCode:
    """Map HTTP status code to default error code.

    Used for wrapping plain HTTPException in structured format.

    Args:
        status_code: HTTP status code.

    Returns:
        Appropriate ErrorCode for the status code.
    """
    mapping = {
        400: ErrorCode.VALIDATION_ERROR,
        401: ErrorCode.AUTH_REQUIRED,
        403: ErrorCode.AUTH_FORBIDDEN,
        404: ErrorCode.NOT_FOUND,
        409: ErrorCode.CONFLICT,
        500: ErrorCode.INTERNAL_ERROR,
        501: ErrorCode.NOT_IMPLEMENTED,
        502: ErrorCode.UPSTREAM_ERROR,
        503: ErrorCode.SERVICE_UNAVAILABLE,
    }
    return mapping.get(status_code, ErrorCode.INTERNAL_ERROR)
