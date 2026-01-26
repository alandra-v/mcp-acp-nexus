"""Shared dependencies for API routes.

FastAPI convention: deps.py contains reusable request dependencies.
All route files should import dependencies from here rather than
defining their own helper functions.

Usage with Annotated (recommended):
    from mcp_acp.api.deps import ConfigDep, ProxyStateDep

    @router.get("/status")
    async def get_status(config: ConfigDep, state: ProxyStateDep) -> StatusResponse:
        ...
"""

from __future__ import annotations

__all__ = [
    # Dependency functions
    "get_approval_store",
    "get_config",
    "get_identity_provider",
    "get_oidc_config",
    "get_policy_path_for_proxy",
    "get_policy_reloader",
    "get_proxy_name",
    "get_proxy_state",
    # Type aliases for Annotated pattern
    "ApprovalStoreDep",
    "ConfigDep",
    "IdentityProviderDep",
    "OIDCConfigDep",
    "PolicyPathDep",
    "PolicyReloaderDep",
    "ProxyNameDep",
    "ProxyStateDep",
]

from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Callable, cast

from fastapi import Depends, HTTPException, Request

if TYPE_CHECKING:
    from mcp_acp.config import AppConfig, OIDCConfig
    from mcp_acp.manager.state import ProxyState
    from mcp_acp.pep.approval_store import ApprovalStore
    from mcp_acp.pep.reloader import PolicyReloader
    from mcp_acp.pips.auth.oidc_provider import OIDCIdentityProvider


# =============================================================================
# Factory for State Getters
# =============================================================================


def _create_state_getter(
    attr_name: str,
    type_hint: str,
    error_detail: str,
) -> Callable[[Request], Any]:
    """Create a dependency function that retrieves a value from app.state.

    This factory reduces duplication across state getter functions that all
    follow the same pattern: get attr from app.state, raise 503 if None.

    Args:
        attr_name: Attribute name on app.state (e.g., "config", "proxy_state").
        type_hint: Type name for cast (e.g., "AppConfig").
        error_detail: Error message for HTTPException.

    Returns:
        A dependency function compatible with FastAPI's Depends().
        Type safety is provided by the explicit type annotations at call sites.
    """

    def getter(request: Request) -> Any:
        value = getattr(request.app.state, attr_name, None)
        if value is None:
            raise HTTPException(status_code=503, detail=error_detail)
        return value

    # Set function metadata for better introspection
    getter.__name__ = f"get_{attr_name}"
    getter.__doc__ = f"Get {type_hint} from app.state.\n\nRaises HTTPException 503 if not available."
    return getter


# =============================================================================
# Dependency Functions (generated via factory)
# =============================================================================

get_proxy_state: Callable[[Request], "ProxyState"] = _create_state_getter(
    "proxy_state",
    "ProxyState",
    "Proxy state not available. Proxy may still be starting.",
)

get_config: Callable[[Request], "AppConfig"] = _create_state_getter(
    "config",
    "AppConfig",
    "Config not available. Proxy may still be starting.",
)

get_policy_reloader: Callable[[Request], "PolicyReloader"] = _create_state_getter(
    "policy_reloader",
    "PolicyReloader",
    "Policy reloader not available. Proxy may still be starting.",
)

get_approval_store: Callable[[Request], "ApprovalStore"] = _create_state_getter(
    "approval_store",
    "ApprovalStore",
    "Approval store not available. Proxy may still be starting.",
)

get_identity_provider: Callable[[Request], "OIDCIdentityProvider"] = _create_state_getter(
    "identity_provider",
    "OIDCIdentityProvider",
    "Identity provider not available. Auth may not be configured.",
)


def get_oidc_config(request: Request) -> "OIDCConfig":
    """Get OIDCConfig from app.state or config file.

    Tries app.state.config first (proxy running), then falls back to
    loading from config file (for standalone API/CLI-style usage).

    Args:
        request: FastAPI request object.

    Returns:
        OIDCConfig instance.

    Raises:
        HTTPException: 400 if OIDC not configured anywhere.
    """
    # Try app.state first (proxy running)
    from mcp_acp.config import AppConfig, OIDCConfig

    config = getattr(request.app.state, "config", None)
    if config is not None and isinstance(config, AppConfig):
        if config.auth is not None and config.auth.oidc is not None:
            return cast(OIDCConfig, config.auth.oidc)

    # Fall back to config file (like CLI does)
    oidc_config = _load_oidc_config_from_file()
    if oidc_config is not None:
        return oidc_config

    raise HTTPException(
        status_code=400,
        detail="Authentication not configured. Add 'auth.oidc' section to config.",
    )


def get_proxy_name(request: Request) -> str | None:
    """Get proxy name from app.state.

    Returns:
        Proxy name if set, None otherwise.
    """
    name: str | None = getattr(request.app.state, "proxy_name", None)
    return name


def get_policy_path_for_proxy(request: Request) -> Path:
    """Get the policy path for the current proxy.

    Args:
        request: FastAPI request object.

    Returns:
        Path to the policy.json file.

    Raises:
        RuntimeError: If proxy_name is not set on app.state.
    """
    from mcp_acp.manager.config import get_proxy_policy_path

    proxy_name = getattr(request.app.state, "proxy_name", None)
    if not proxy_name:
        raise RuntimeError("proxy_name not set on app.state")
    return get_proxy_policy_path(proxy_name)


def _load_oidc_config_from_file() -> "OIDCConfig | None":
    """Load OIDC config from manager.json.

    Returns:
        OIDCConfig if found and valid, None otherwise.
    """
    # Import here to avoid circular imports
    from mcp_acp.manager.config import get_manager_config_path, load_manager_config

    try:
        config_path = get_manager_config_path()
        if not config_path.exists():
            return None

        config = load_manager_config()
        if config.auth is None or config.auth.oidc is None:
            return None

        return config.auth.oidc
    except Exception:
        return None


# =============================================================================
# Type Aliases for Annotated Pattern
# =============================================================================
# These allow clean route signatures:
#     async def endpoint(config: ConfigDep) -> Response:
# Instead of:
#     async def endpoint(config: AppConfig = Depends(get_config)) -> Response:


ProxyStateDep = Annotated["ProxyState", Depends(get_proxy_state)]
ConfigDep = Annotated["AppConfig", Depends(get_config)]
PolicyReloaderDep = Annotated["PolicyReloader", Depends(get_policy_reloader)]
ApprovalStoreDep = Annotated["ApprovalStore", Depends(get_approval_store)]
IdentityProviderDep = Annotated["OIDCIdentityProvider", Depends(get_identity_provider)]
OIDCConfigDep = Annotated["OIDCConfig", Depends(get_oidc_config)]
ProxyNameDep = Annotated[str | None, Depends(get_proxy_name)]
PolicyPathDep = Annotated[Path, Depends(get_policy_path_for_proxy)]
