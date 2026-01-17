"""Authentication API schemas."""

from __future__ import annotations

__all__ = [
    "AuthStatusResponse",
    "DeviceFlowPollResponse",
    "DeviceFlowStartResponse",
    "FederatedLogoutResponse",
    "LogoutResponse",
    "NotifyResponse",
]

from typing import Literal

from pydantic import BaseModel


class AuthStatusResponse(BaseModel):
    """Authentication status response."""

    authenticated: bool
    subject_id: str | None = None
    email: str | None = None
    name: str | None = None
    token_expires_in_hours: float | None = None
    has_refresh_token: bool | None = None
    storage_backend: str | None = None
    provider: str | None = None  # OIDC issuer domain (e.g., "Auth0")


class DeviceFlowStartResponse(BaseModel):
    """Response when starting device flow."""

    user_code: str
    verification_uri: str
    verification_uri_complete: str | None = None
    expires_in: int
    interval: int
    poll_endpoint: str


class DeviceFlowPollResponse(BaseModel):
    """Response when polling device flow."""

    status: Literal["pending", "complete", "expired", "denied", "error"]
    message: str | None = None


class LogoutResponse(BaseModel):
    """Logout response."""

    status: str
    message: str


class FederatedLogoutResponse(BaseModel):
    """Federated logout response."""

    status: str
    logout_url: str
    message: str


class NotifyResponse(BaseModel):
    """Response for notify endpoints."""

    status: str
    message: str
