"""Debug API endpoints for testing.

WARNING: These endpoints are for development/testing only.
Do not enable in production.

Routes mounted at: /api/debug

Testing shutdowns:
- Delete an audit file while proxy is running (e.g., rm ~/.mcp-acp/.../auth.jsonl)
- Audit health monitor will detect and trigger security shutdown
"""

from __future__ import annotations

__all__ = ["router"]

from fastapi import APIRouter

router = APIRouter()


# No debug endpoints currently - security shutdowns are tested by deleting audit files
