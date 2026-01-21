"""Application configuration for mcp-acp.

Defines configuration models for logging, backend connections, and proxy behavior.
User creates config via `mcp-acp init`. Config is stored at the OS-appropriate
location (via click.get_app_dir), log_dir is user-specified.

Example usage:
    # Load from config file
    config = AppConfig.load_from_files(config_path)

    # Save new configuration
    config.save_to_file(config_path)
"""

from __future__ import annotations

__all__ = [
    "DEFAULT_LOG_DIR",
    "AppConfig",
    "AuthConfig",
    "BackendConfig",
    "HITLConfig",
    "HttpTransportConfig",
    "LoggingConfig",
    "MTLSConfig",
    "OIDCConfig",
    "ProxyConfig",
    "StdioAttestationConfig",
    "StdioTransportConfig",
]

import json
import os
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from mcp_acp.constants import (
    APP_NAME,
    DEFAULT_APPROVAL_TTL_SECONDS,
    DEFAULT_HITL_TIMEOUT_SECONDS,
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    MAX_APPROVAL_TTL_SECONDS,
    MAX_HITL_TIMEOUT_SECONDS,
    MAX_HTTP_TIMEOUT_SECONDS,
    MIN_APPROVAL_TTL_SECONDS,
    MIN_HITL_TIMEOUT_SECONDS,
    MIN_HTTP_TIMEOUT_SECONDS,
)
from mcp_acp.context.resource import SideEffect
from mcp_acp.utils.file_helpers import load_validated_json, require_file_exists


# =============================================================================
# Platform-specific defaults
# =============================================================================


def _get_platform_log_dir() -> str:
    """Get platform-appropriate base log directory following OS conventions.

    Returns:
        Platform-specific base log directory path (unexpanded).
        Proxy logs go in <base>/mcp-acp/proxies/default/.

    Platform conventions:
        - macOS: ~/Library/Logs (Apple standard, integrates with Console.app)
        - Linux: ~/.local/state (XDG Base Directory Specification for logs/state)
        - Windows: ~/AppData/Local (standard for app data)
    """
    if sys.platform == "darwin":
        return "~/Library/Logs"
    elif sys.platform == "win32":
        return "~/AppData/Local"
    else:
        # Linux/Unix: XDG_STATE_HOME is for logs, history, state
        # Falls back to ~/.local/state per XDG spec
        return os.environ.get("XDG_STATE_HOME", "~/.local/state")


# Default base log directory (platform-specific, follows OS conventions)
DEFAULT_LOG_DIR = _get_platform_log_dir()


# =============================================================================
# Authentication Configuration (Zero Trust - all features mandatory)
# =============================================================================


class OIDCConfig(BaseModel):
    """Auth0/OIDC configuration for user authentication.

    All fields are required - Zero Trust requires authenticated users.

    Attributes:
        issuer: OIDC issuer URL (e.g., "https://your-tenant.auth0.com").
        client_id: Auth0 application client ID.
        audience: API audience for token validation.
        scopes: OAuth scopes to request (default includes offline_access for refresh).
    """

    issuer: str = Field(min_length=1)
    client_id: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    scopes: list[str] = Field(
        default=["openid", "profile", "email", "offline_access"],
        description="OAuth scopes to request",
    )


class MTLSConfig(BaseModel):
    """mTLS configuration for secure backend connections.

    Required when backend uses HTTPS. Provides mutual authentication
    between proxy and backend server.

    Attributes:
        client_cert_path: Path to client certificate (PEM format).
        client_key_path: Path to client private key (PEM format).
        ca_bundle_path: Path to CA bundle for server verification (PEM format).
    """

    client_cert_path: str = Field(min_length=1)
    client_key_path: str = Field(min_length=1)
    ca_bundle_path: str = Field(min_length=1)


class AuthConfig(BaseModel):
    """Authentication configuration for Zero Trust.

    All authentication is mandatory - there is no option to disable auth.
    This ensures Zero Trust compliance: every request has a verified identity.

    Note: Device health (disk encryption, firewall) is checked at runtime,
    not configured here. If checks fail, proxy won't start.

    Attributes:
        oidc: OIDC/Auth0 configuration for user authentication.
        mtls: mTLS configuration (required for HTTPS backends).
    """

    oidc: OIDCConfig
    mtls: MTLSConfig | None = None  # Required only for HTTPS backends


# =============================================================================
# Logging Configuration
# =============================================================================


class LoggingConfig(BaseModel):
    """Logging configuration settings.

    The log_dir specifies a base directory. Logs are stored in
    <log_dir>/mcp-acp/proxies/default/ with this structure:
        <log_dir>/
        └── mcp-acp/
            └── proxy/
                ├── debug/                  # Only created when log_level=DEBUG
                │   ├── client_wire.jsonl
                │   └── backend_wire.jsonl
                ├── system/
                │   ├── system.jsonl
                │   └── config_history.jsonl
                └── audit/                  # Always enabled (security audit trail)
                    └── operations.jsonl

    Attributes:
        log_dir: Base directory for logs. Platform-specific default:
            - macOS: ~/Library/Logs
            - Linux: $XDG_STATE_HOME (~/.local/state)
        log_level: Logging level (DEBUG or INFO). DEBUG enables wire logs.
        include_payloads: Whether to include full message payloads in debug logs.
    """

    log_dir: str = Field(default=DEFAULT_LOG_DIR, min_length=1)
    log_level: Literal["DEBUG", "INFO"] = "INFO"
    include_payloads: bool = True


class StdioAttestationConfig(BaseModel):
    """Binary attestation configuration for STDIO backends.

    Two verification modes (can use both):

    1. SLSA Provenance (build-time):
       - slsa_owner: GitHub owner (user/org) for attestation verification
       - Proves binary was built from trusted CI/CD pipeline

    2. Runtime checks:
       - expected_sha256: Verify binary hash matches expected
       - require_signature: Require valid code signature (macOS)

    Attributes:
        slsa_owner: GitHub owner for SLSA attestation verification.
            If set, runs `gh attestation verify --owner <owner> <binary>`.
            Requires `gh` CLI to be installed and authenticated.
        expected_sha256: Expected SHA-256 hash of the binary (hex string).
            If set, binary hash is verified before spawn.
        require_signature: Whether to require valid code signature (macOS only).
            Default False (opt-in). Ignored on non-macOS platforms.
    """

    slsa_owner: str | None = None
    expected_sha256: str | None = None
    require_signature: bool = False  # Opt-in for macOS codesign


class StdioTransportConfig(BaseModel):
    """STDIO transport configuration.

    Attributes:
        command: Command to launch backend server.
        args: Arguments to pass to backend command.
        attestation: Optional binary attestation configuration.
            If set, binary is verified before spawning.
    """

    command: str = Field(min_length=1)
    args: list[str] = Field(default_factory=list)
    attestation: StdioAttestationConfig | None = None


class HttpTransportConfig(BaseModel):
    """Streamable HTTP transport configuration.

    Attributes:
        url: Backend server URL (e.g., "http://localhost:3010/mcp").
        timeout: Connection timeout in seconds (1-300).
    """

    url: str = Field(min_length=1, pattern=r"^https?://")
    timeout: int = Field(
        default=DEFAULT_HTTP_TIMEOUT_SECONDS,
        ge=MIN_HTTP_TIMEOUT_SECONDS,
        le=MAX_HTTP_TIMEOUT_SECONDS,
    )


class BackendConfig(BaseModel):
    """Backend server configuration for a single server.

    Supports STDIO and Streamable HTTP transports. User configures via `init`.

    Transport selection:
    - "stdio": Use STDIO transport exclusively (stdio config must be present).
    - "streamablehttp": Use HTTP transport exclusively (http config must be present).
    - "auto": Auto-detect - prefer HTTP if configured and reachable, else STDIO.

    Attributes:
        server_name: Name of the server (for display/reference).
        transport: Transport type ("stdio", "streamablehttp", or "auto").
        stdio: STDIO transport configuration (command, args).
        http: Streamable HTTP transport configuration (url, timeout).
    """

    server_name: str = Field(min_length=1)
    transport: Literal["stdio", "streamablehttp", "auto"] = "auto"
    stdio: StdioTransportConfig | None = None
    http: HttpTransportConfig | None = None


class ProxyConfig(BaseModel):
    """Proxy server configuration settings.

    Attributes:
        name: Proxy server name for identification.
    """

    name: str = Field(default=APP_NAME, min_length=1)


class HITLConfig(BaseModel):
    """Configuration for Human-in-the-Loop approval.

    Attributes:
        timeout_seconds: How long to wait for user response (default: 60s).
            Must be between 5-300 seconds.
        default_on_timeout: What to do if user doesn't respond (always "deny").
        approval_ttl_seconds: How long cached approvals remain valid (default: 600s).
            Must be between 300-900 seconds (5-15 minutes).

    Important:
        The timeout should be shorter than your MCP client's request timeout.
        If the client times out before the user responds, the request will fail
        even if the user later approves. See constants.py for details.

    Note:
        cache_side_effects has moved to per-rule policy configuration.
        Set it on individual HITL rules to control which side effects can be cached.
    """

    timeout_seconds: int = Field(
        default=DEFAULT_HITL_TIMEOUT_SECONDS,
        ge=MIN_HITL_TIMEOUT_SECONDS,
        le=MAX_HITL_TIMEOUT_SECONDS,
    )
    default_on_timeout: Literal["deny"] = "deny"

    approval_ttl_seconds: int = Field(
        default=DEFAULT_APPROVAL_TTL_SECONDS,
        ge=MIN_APPROVAL_TTL_SECONDS,
        le=MAX_APPROVAL_TTL_SECONDS,
    )


class AppConfig(BaseModel):
    """Main application configuration for mcp-acp.

    Contains all configuration sections including authentication, logging,
    backend server, proxy settings, and HITL (Human-in-the-Loop) configuration.

    Zero Trust: Authentication is mandatory. The proxy will not start without
    valid auth configuration. There is no unauthenticated fallback.

    Attributes:
        auth: Authentication configuration (OIDC, mTLS). Required for proxy to start.
        logging: Logging configuration (log level, paths, payload settings).
        backend: Backend server configuration (STDIO or Streamable HTTP transport).
        proxy: Proxy server configuration (name).
        hitl: Human-in-the-Loop configuration (timeout, approval TTL, caching).
    """

    auth: AuthConfig | None = None  # Validated at runtime - proxy won't start without it
    logging: LoggingConfig
    backend: BackendConfig
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    hitl: HITLConfig = Field(default_factory=HITLConfig)

    def save_to_file(self, config_path: Path) -> None:
        """Save configuration to JSON file.

        Creates parent directories if they don't exist.
        Sets secure permissions (0o700) on the config directory.

        Args:
            config_path: Path where mcp_acp_config.json should be saved.
        """
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.parent.chmod(0o700)

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(), f, indent=2)

        config_path.chmod(0o600)

    @classmethod
    def load_from_files(cls, config_path: Path) -> "AppConfig":
        """Load configuration from JSON file.

        Args:
            config_path: Path to the config file (mcp_acp_config.json).

        Returns:
            AppConfig instance with loaded configuration.

        Raises:
            FileNotFoundError: If config file doesn't exist.
            ValueError: If config file is invalid or missing required fields.
        """
        require_file_exists(config_path, file_type="configuration")
        return load_validated_json(
            config_path,
            cls,
            file_type="config",
            recovery_hint="Run 'mcp-acp init' to reconfigure.",
            encoding="utf-8",
        )
