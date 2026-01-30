"""Proxy management endpoints (list, detail, create, delete, config-snippet)."""

from __future__ import annotations

__all__ = ["router", "STDIO_TRANSPORTS", "HTTP_TRANSPORTS"]

from fastapi import APIRouter

router = APIRouter(prefix="/api/manager", tags=["proxies"])

# Transport types that require specific configuration
STDIO_TRANSPORTS = frozenset({"stdio", "auto"})
HTTP_TRANSPORTS = frozenset({"streamablehttp", "auto"})

# Import submodules to register routes on the shared router.
# These imports MUST come after `router` is defined.
from . import creation as creation  # noqa: E402, F401
from . import deletion as deletion  # noqa: E402, F401
from . import listing as listing  # noqa: E402, F401
from . import snippet as snippet  # noqa: E402, F401
