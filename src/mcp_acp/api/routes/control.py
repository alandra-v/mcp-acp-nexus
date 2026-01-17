"""Proxy control API endpoints.

Provides:
- GET /status - Current proxy and policy status
- POST /reload-policy - Hot reload policy from disk

Note: Proxy lifecycle management (start/stop/restart) will be added
in the multi-proxy Manager phase. See ui-progress.md.
"""

__all__ = ["router"]

from fastapi import APIRouter

from mcp_acp.api.deps import PolicyReloaderDep
from mcp_acp.api.schemas import ProxyStatus, ReloadResponse

router = APIRouter()


@router.get("/status")
async def get_status(reloader: PolicyReloaderDep) -> ProxyStatus:
    """Get current proxy and policy status.

    Returns:
        ProxyStatus with uptime, policy version, rules count, reload info.
    """
    return ProxyStatus(
        running=True,
        uptime_seconds=reloader.uptime_seconds,
        policy_version=reloader.current_version,
        policy_rules_count=reloader.current_rules_count,
        last_reload_at=reloader.last_reload_at,
        reload_count=reloader.reload_count,
    )


@router.post("/reload-policy")
async def reload_policy(reloader: PolicyReloaderDep) -> ReloadResponse:
    """Reload policy from disk without restarting proxy.

    Validates the new policy before applying. On validation failure,
    the old policy remains active (Last Known Good pattern).

    Returns:
        ReloadResponse with status, rule counts, and version info.
    """
    result = await reloader.reload()

    return ReloadResponse(
        status=result.status,
        old_rules_count=result.old_rules_count,
        new_rules_count=result.new_rules_count,
        approvals_cleared=result.approvals_cleared,
        error=result.error,
        policy_version=result.policy_version,
    )
