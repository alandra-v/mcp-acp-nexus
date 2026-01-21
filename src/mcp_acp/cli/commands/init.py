"""Init command for mcp-acp CLI.

Handles interactive and non-interactive configuration initialization.
"""

from __future__ import annotations

__all__ = ["init"]

import sys
from pathlib import Path
from typing import Literal, cast

import click

from mcp_acp.config import (
    DEFAULT_LOG_DIR,
    AppConfig,
    AuthConfig,
    BackendConfig,
    HttpTransportConfig,
    LoggingConfig,
    MTLSConfig,
    OIDCConfig,
    StdioAttestationConfig,
    StdioTransportConfig,
)
from mcp_acp.constants import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    HEALTH_CHECK_TIMEOUT_SECONDS,
)
from mcp_acp.pdp import create_default_policy
from mcp_acp.utils.policy import get_policy_path, save_policy
from mcp_acp.utils.history_logging.policy_logger import log_policy_created
from mcp_acp.utils.config import (
    ensure_directories,
    get_config_history_path,
    get_config_path,
    get_policy_history_path,
)
from mcp_acp.utils.history_logging import log_config_created
from mcp_acp.utils.transport import check_http_health, validate_mtls_config
from mcp_acp.utils.validation import is_valid_oidc_issuer, validate_sha256_hex
from mcp_acp.security.auth.token_storage import create_token_storage

from ..prompts import prompt_auth_config, prompt_http_config, prompt_stdio_config, prompt_with_retry
from ..styling import style_dim, style_error, style_header, style_success, style_warning


def _require_flag(value: str | None, flag_name: str, message: str | None = None) -> str:
    """Validate a required CLI flag, exit with error if missing.

    Args:
        value: The flag value to validate.
        flag_name: Name of the flag (without --) for error message.
        message: Optional custom error message (overrides default).

    Returns:
        The validated non-None value.

    Raises:
        SystemExit: If value is None or empty.
    """
    if not value:
        msg = message or f"--{flag_name} is required"
        click.echo(style_error(f"Error: {msg}"), err=True)
        sys.exit(1)
    return value


def _check_oidc_change_warning(
    old_config: AppConfig | None,
    new_auth_config: AuthConfig,
) -> None:
    """Warn if OIDC settings changed and user has stored tokens.

    When OIDC settings change (issuer, client_id, audience), existing tokens
    become invalid. This warns the user to re-authenticate.

    Args:
        old_config: Previous configuration (None if no config existed).
        new_auth_config: New authentication configuration being saved.
    """
    if old_config is None:
        return

    old_oidc = old_config.auth.oidc if old_config.auth else None
    new_oidc = new_auth_config.oidc if new_auth_config else None

    # Check if OIDC settings changed
    oidc_changed = False
    if old_oidc and new_oidc:
        # Both have OIDC - check if settings differ
        if (
            old_oidc.issuer != new_oidc.issuer
            or old_oidc.client_id != new_oidc.client_id
            or old_oidc.audience != new_oidc.audience
        ):
            oidc_changed = True
    elif old_oidc and not new_oidc:
        # Had OIDC, now removed
        oidc_changed = True
    elif not old_oidc and new_oidc:
        # Didn't have OIDC, now added - no warning needed (no old token)
        pass

    if not oidc_changed:
        return

    # Check if tokens exist
    try:
        storage = create_token_storage(old_oidc)
        if storage.exists():
            click.echo()
            click.echo(style_warning("OIDC settings changed"))
            click.echo("  Your stored authentication token was created with different settings.")
            click.echo("  You will need to run 'mcp-acp auth login' to re-authenticate.")
            click.echo()
    except Exception:
        # Can't check token storage - don't warn, not critical
        pass


def _create_policy_only(config: AppConfig, policy_path: Path) -> None:
    """Create policy file using existing config's log_dir.

    Args:
        config: Existing AppConfig (for log_dir).
        policy_path: Path to save policy file.
    """
    policy = create_default_policy()
    save_policy(policy, policy_path)

    # Log policy creation to history
    ensure_directories(config)
    log_policy_created(
        get_policy_history_path(config),
        policy_path,
        policy.model_dump(),
        source="cli_init",
    )


def _create_and_save_config(
    config_path: Path,
    log_dir: str,
    log_level: str,
    include_payloads: bool,
    server_name: str,
    connection_type: str,
    stdio_config: StdioTransportConfig | None,
    http_config: HttpTransportConfig | None,
    auth_config: AuthConfig,
) -> None:
    """Create and save configuration and policy files.

    Args:
        config_path: Path to save config file.
        log_dir: Log directory path.
        log_level: Logging level.
        include_payloads: Whether to include payloads in debug logs.
        server_name: Backend server name.
        connection_type: Connection type (stdio, http, or both).
        stdio_config: STDIO transport config (if applicable).
        http_config: HTTP transport config (if applicable).
        auth_config: Authentication configuration.

    Raises:
        OSError: If files cannot be saved.
    """
    log_level_literal = cast(
        Literal["DEBUG", "INFO"],
        log_level.upper(),
    )

    # Determine transport setting based on connection type
    # CLI uses "both" -> config uses "auto" (auto-detect)
    transport: Literal["stdio", "streamablehttp", "auto"]
    if connection_type == "stdio":
        transport = "stdio"
    elif connection_type == "http":
        transport = "streamablehttp"
    elif connection_type == "both":
        transport = "auto"  # auto-detect at runtime
    else:
        raise ValueError(f"Invalid connection_type: {connection_type}")

    config = AppConfig(
        auth=auth_config,
        logging=LoggingConfig(
            log_dir=log_dir,
            log_level=log_level_literal,
            include_payloads=include_payloads,
        ),
        backend=BackendConfig(
            server_name=server_name,
            transport=transport,
            stdio=stdio_config,
            http=http_config,
        ),
    )

    # Save configuration
    config.save_to_file(config_path)

    # Log config creation to history (with versioning and checksum)
    ensure_directories(config)
    log_config_created(
        get_config_history_path(config),
        config_path,
        config.model_dump(),
        source="cli_init",
    )

    # Create default policy file
    policy_path = get_policy_path()
    _create_policy_only(config, policy_path)

    # Display result
    click.echo("\n" + style_success(f"Configuration saved to {config_path}"))
    click.echo(style_success(f"Policy saved to {policy_path}"))
    if transport == "auto":
        click.echo("Transport: auto-detect (prefers HTTP when reachable)")
    else:
        click.echo(f"Transport: {transport}")
    click.echo("\nRun 'mcp-acp start' to test the proxy manually.")


def _run_interactive_init(
    log_dir: str | None,
    log_level: str,
    server_name: str | None,
) -> tuple[str, str, bool, str, str, StdioTransportConfig | None, HttpTransportConfig | None, AuthConfig]:
    """Run interactive configuration wizard.

    Args:
        log_dir: Pre-provided log directory or None.
        log_level: Pre-provided log level.
        server_name: Pre-provided server name or None.

    Returns:
        Tuple of (log_dir, log_level, include_payloads, server_name, connection_type,
        stdio_config, http_config, auth_config).

    Raises:
        click.Abort: If user aborts during HTTP configuration.
    """
    click.echo("\nWelcome to mcp-acp!\n")
    click.echo(f"Config will be saved to: {get_config_path()}\n")

    # Logging settings
    click.echo(style_header("Logging"))
    log_dir = log_dir or prompt_with_retry(f"Log directory (default: {DEFAULT_LOG_DIR})")
    click.echo("  DEBUG enables debug wire logs (client <-> proxy <-> backend)")
    log_level = click.prompt(
        "Log level",
        type=click.Choice(["DEBUG", "INFO"], case_sensitive=False),
        default=log_level,
    )

    # Payload logging (only relevant for DEBUG)
    include_payloads = True  # default
    if log_level.upper() == "DEBUG":
        click.echo("\n  Include full message payloads in debug logs?")
        click.echo("    Yes = more verbose, shows actual content")
        click.echo("    No  = only method names and metadata")
        include_payloads = click.confirm("  Include payloads", default=True)

    # Backend settings
    click.echo()
    click.echo(style_header("Backend"))
    server_name = server_name or prompt_with_retry("Server name")

    # Connection type selection
    click.echo("\nHow do you connect to this server?")
    click.echo("  1. Local command (STDIO) - spawn a process like npx, uvx, python")
    click.echo("  2. Remote URL (Streamable HTTP) - connect to http://...")
    click.echo("  3. Both (configure both, auto-detect at runtime)")
    choice = click.prompt("Select", type=click.Choice(["1", "2", "3"]), default="1")

    stdio_config: StdioTransportConfig | None = None
    http_config: HttpTransportConfig | None = None

    if choice == "1":
        connection_type = "stdio"
        stdio_config = prompt_stdio_config()
    elif choice == "2":
        connection_type = "http"
        http_config = prompt_http_config()
    else:  # choice == "3"
        connection_type = "both"
        click.echo("\n  Auto-detect behavior: HTTP is tried first. If unreachable,")
        click.echo("  falls back to STDIO automatically.\n")
        stdio_config = prompt_stdio_config()
        http_config = prompt_http_config()

    # Authentication settings
    auth_config = prompt_auth_config(http_config)

    return (
        log_dir,
        log_level,
        include_payloads,
        server_name,
        connection_type,
        stdio_config,
        http_config,
        auth_config,
    )


def _run_non_interactive_init(
    log_dir: str | None,
    log_level: str,
    include_payloads: bool | None,
    server_name: str | None,
    connection_type: str | None,
    command: str | None,
    args: str | None,
    url: str | None,
    timeout: int,
    # Auth options
    oidc_issuer: str | None,
    oidc_client_id: str | None,
    oidc_audience: str | None,
    mtls_cert: str | None,
    mtls_key: str | None,
    mtls_ca: str | None,
    # Attestation options
    attestation_slsa_owner: str | None,
    attestation_sha256: str | None,
    attestation_require_signature: bool | None,
) -> tuple[str, str, bool, str, str, StdioTransportConfig | None, HttpTransportConfig | None, AuthConfig]:
    """Run non-interactive configuration setup.

    Args:
        log_dir: Log directory path.
        log_level: Logging level.
        include_payloads: Whether to include payloads in debug logs (None = default True).
        server_name: Backend server name.
        connection_type: Transport type (stdio, http, both).
        command: STDIO command.
        args: STDIO arguments (comma-separated).
        url: HTTP URL.
        timeout: HTTP timeout.
        oidc_issuer: OIDC issuer URL.
        oidc_client_id: Auth0 client ID.
        oidc_audience: API audience.
        mtls_cert: mTLS client certificate path.
        mtls_key: mTLS client key path.
        mtls_ca: mTLS CA bundle path.
        attestation_slsa_owner: GitHub owner for SLSA attestation.
        attestation_sha256: Expected SHA-256 hash of STDIO binary.
        attestation_require_signature: Require code signature (macOS).

    Returns:
        Tuple of (log_dir, log_level, include_payloads, server_name, connection_type,
        stdio_config, http_config, auth_config).

    Raises:
        SystemExit: If required flags are missing.
    """
    # Validate required flags
    log_dir = _require_flag(log_dir, "log-dir")
    server_name = _require_flag(server_name, "server-name")
    connection_type = _require_flag(connection_type, "connection-type")

    # Validate auth flags
    if not oidc_issuer or not oidc_client_id or not oidc_audience:
        click.echo(
            style_error("Error: --oidc-issuer, --oidc-client-id, and --oidc-audience are required"), err=True
        )
        sys.exit(1)

    # Validate OIDC issuer URL format (must be HTTPS per OpenID Connect spec)
    if not is_valid_oidc_issuer(oidc_issuer):
        click.echo(style_error("Error: --oidc-issuer must start with https://"), err=True)
        sys.exit(1)

    # Validate attestation SHA-256 format if provided
    if attestation_sha256:
        is_valid, normalized = validate_sha256_hex(attestation_sha256)
        if not is_valid:
            click.echo(style_error("Error: --attestation-sha256 must be a 64-character hex string"), err=True)
            sys.exit(1)
        attestation_sha256 = normalized

    stdio_config: StdioTransportConfig | None = None
    http_config: HttpTransportConfig | None = None

    # Validate transport-specific flags
    if connection_type.lower() in ("stdio", "both"):
        if not command or not args:
            click.echo(style_error("Error: --command and --args required for stdio connection"), err=True)
            sys.exit(1)
        args_list = [arg.strip() for arg in args.split(",") if arg.strip()]

        # Build attestation config if any attestation option provided
        attestation_config: StdioAttestationConfig | None = None
        if attestation_slsa_owner or attestation_sha256 or attestation_require_signature:
            attestation_config = StdioAttestationConfig(
                slsa_owner=attestation_slsa_owner,
                expected_sha256=attestation_sha256,
                require_signature=attestation_require_signature or False,
            )
            click.echo(style_success("Binary attestation configured."))

        stdio_config = StdioTransportConfig(command=command, args=args_list, attestation=attestation_config)

    if connection_type.lower() in ("http", "both"):
        url = _require_flag(url, "url", "--url required for http connection")
        http_config = HttpTransportConfig(url=url, timeout=timeout)

        # Test HTTP connectivity
        click.echo(f"Testing connection to {url}...")
        try:
            check_http_health(url, timeout=min(timeout, HEALTH_CHECK_TIMEOUT_SECONDS))
            click.echo(style_success("Server is reachable."))
        except Exception:
            click.echo(f"Health check failed: could not reach {url}", err=True)
            click.echo("Config will be saved anyway. Server may be offline.", err=True)

    # Build auth config
    oidc_config = OIDCConfig(
        issuer=oidc_issuer,
        client_id=oidc_client_id,
        audience=oidc_audience,
    )

    mtls_config: MTLSConfig | None = None
    if mtls_cert and mtls_key and mtls_ca:
        # Validate mTLS certificates
        click.echo("Validating mTLS certificates...")
        errors = validate_mtls_config(mtls_cert, mtls_key, mtls_ca)
        if errors:
            click.echo(style_error("Error: mTLS certificate validation failed:"), err=True)
            for error in errors:
                click.echo(f"  - {error}", err=True)
            sys.exit(1)
        click.echo(style_success("mTLS certificates valid."))

        mtls_config = MTLSConfig(
            client_cert_path=mtls_cert,
            client_key_path=mtls_key,
            ca_bundle_path=mtls_ca,
        )

    auth_config = AuthConfig(
        oidc=oidc_config,
        mtls=mtls_config,
    )

    # Default include_payloads to True if not specified
    resolved_include_payloads = include_payloads if include_payloads is not None else True

    return (
        log_dir,
        log_level,
        resolved_include_payloads,
        server_name,
        connection_type,
        stdio_config,
        http_config,
        auth_config,
    )


@click.command()
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Skip prompts, require all options via flags",
)
@click.option(
    "--log-dir",
    help=f"Log directory path (default: {DEFAULT_LOG_DIR})",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO"], case_sensitive=False),
    default="INFO",
    help="Logging verbosity (default: INFO). DEBUG enables debug wire logs.",
)
@click.option(
    "--include-payloads/--no-include-payloads",
    default=None,
    help="Include message payloads in debug logs (default: True, only relevant with DEBUG).",
)
@click.option("--server-name", help="Backend server name")
@click.option(
    "--connection-type",
    type=click.Choice(["stdio", "http", "both"], case_sensitive=False),
    help="Transport: stdio (local), http (remote), both (HTTP with STDIO fallback)",
)
@click.option("--command", help="Backend command for STDIO (e.g., npx)")
@click.option("--args", help="Backend arguments for STDIO (comma-separated)")
@click.option("--url", help="Backend URL for HTTP (e.g., http://localhost:3010/mcp)")
@click.option(
    "--timeout",
    type=int,
    default=DEFAULT_HTTP_TIMEOUT_SECONDS,
    help=f"Connection timeout for HTTP (default: {DEFAULT_HTTP_TIMEOUT_SECONDS})",
)
# Auth options
@click.option("--oidc-issuer", help="OIDC issuer URL (e.g., https://your-tenant.auth0.com)")
@click.option("--oidc-client-id", help="Auth0 client ID")
@click.option("--oidc-audience", help="API audience for token validation")
@click.option(
    "--mtls-cert",
    help="Client certificate for mTLS (PEM). Presented to backend to prove proxy identity.",
)
@click.option(
    "--mtls-key",
    help="Client private key for mTLS (PEM). Must match --mtls-cert. Keep secure (0600).",
)
@click.option(
    "--mtls-ca",
    help="CA bundle for mTLS (PEM). Used to verify backend server's certificate.",
)
# STDIO attestation options
@click.option(
    "--attestation-slsa-owner",
    help="GitHub owner for SLSA attestation verification. Requires `gh` CLI.",
)
@click.option(
    "--attestation-sha256",
    help="Expected SHA-256 hash of the STDIO backend binary (64 hex chars).",
)
@click.option(
    "--attestation-require-signature/--no-attestation-require-signature",
    default=None,
    help="Require valid code signature on macOS. Ignored on other platforms.",
)
@click.option("--force", is_flag=True, help="Overwrite existing config without prompting")
def init(
    non_interactive: bool,
    log_dir: str | None,
    log_level: str,
    include_payloads: bool | None,
    server_name: str | None,
    connection_type: str | None,
    command: str | None,
    args: str | None,
    url: str | None,
    timeout: int,
    oidc_issuer: str | None,
    oidc_client_id: str | None,
    oidc_audience: str | None,
    mtls_cert: str | None,
    mtls_key: str | None,
    mtls_ca: str | None,
    attestation_slsa_owner: str | None,
    attestation_sha256: str | None,
    attestation_require_signature: bool | None,
    force: bool,
) -> None:
    """Initialize proxy configuration.

    Creates configuration at the OS-appropriate location:
    - macOS: ~/Library/Application Support/mcp-acp/
    - Linux: ~/.config/mcp-acp/
    - Windows: C:\\Users\\<user>\\AppData\\Roaming\\mcp-acp/

    \b
    Connection types:
    - stdio: Spawn a local server process (e.g., npx, uvx, python).
            Requires --command and --args.
    - http:  Connect to a remote server via Streamable HTTP URL.
            Requires --url. Warns if server is unreachable but saves config.
    - auto:  Configure both transports with automatic fallback.
            At runtime: tries HTTP first, falls back to STDIO if
            HTTP is unreachable. Useful for development (local)
            vs production (remote) flexibility.

    \b
    mTLS (Mutual TLS):
    For HTTPS backends requiring client certificate authentication,
    provide all three mTLS options: --mtls-cert, --mtls-key, --mtls-ca.
    Get certificates from your IT team or generate for testing.
    See 'docs/auth.md' for certificate generation instructions.

    \b
    Binary Attestation (STDIO only):
    Verify STDIO backend binaries before spawning. Options:
    - --attestation-slsa-owner: GitHub owner for SLSA provenance verification
    - --attestation-sha256: Expected SHA-256 hash of the binary
    - --attestation-require-signature: Require code signature (macOS only)

    Use --non-interactive with required flags for scripted setup.
    """
    config_path = get_config_path()
    policy_path = get_policy_path()

    config_exists = config_path.exists()
    policy_exists = policy_path.exists()

    # Upgrade path: config exists but policy missing - just create policy
    if config_exists and not policy_exists:
        click.echo("Policy file missing. Creating default policy...")
        try:
            existing_config = AppConfig.load_from_files(config_path)
            _create_policy_only(existing_config, policy_path)
            click.echo(style_success(f"Policy created at {policy_path}"))
            return
        except ValueError as e:
            click.echo(style_error(f"Error: Cannot load existing config: {e}"), err=True)
            click.echo("Fix the config or use --force to recreate both files.", err=True)
            sys.exit(1)

    # If config exists, ask to overwrite (unless --force)
    # If only policy exists, proceed - user wants to recreate config
    if config_exists and not force:
        if non_interactive:
            click.echo(style_error("Error: Config already exists. Use --force to overwrite."), err=True)
            sys.exit(1)
        if not click.confirm("Config already exists. Overwrite?", default=False):
            click.echo(style_dim("Aborted."))
            sys.exit(0)

    # Load existing config to check for OIDC changes later
    old_config: AppConfig | None = None
    if config_exists:
        try:
            old_config = AppConfig.load_from_files(config_path)
        except Exception:
            # Can't load old config - that's fine, we'll skip the warning
            pass

    # Gather configuration values
    try:
        if non_interactive:
            (
                log_dir,
                log_level,
                include_payloads,
                server_name,
                connection_type,
                stdio_config,
                http_config,
                auth_config,
            ) = _run_non_interactive_init(
                log_dir,
                log_level,
                include_payloads,
                server_name,
                connection_type,
                command,
                args,
                url,
                timeout,
                oidc_issuer,
                oidc_client_id,
                oidc_audience,
                mtls_cert,
                mtls_key,
                mtls_ca,
                attestation_slsa_owner,
                attestation_sha256,
                attestation_require_signature,
            )
        else:
            (
                log_dir,
                log_level,
                include_payloads,
                server_name,
                connection_type,
                stdio_config,
                http_config,
                auth_config,
            ) = _run_interactive_init(log_dir, log_level, server_name)
    except click.Abort:
        click.echo(style_dim("Aborted."))
        sys.exit(0)

    # Warn if OIDC settings changed and user has stored tokens
    _check_oidc_change_warning(old_config, auth_config)

    # Create and save configuration (always creates both config and policy)
    # Note: log_dir, server_name, connection_type are guaranteed to be str after
    # _run_non_interactive_init (validates and exits) or _run_interactive_init (prompts until valid)
    assert log_dir is not None
    assert server_name is not None
    assert connection_type is not None
    try:
        _create_and_save_config(
            config_path,
            log_dir,
            log_level,
            include_payloads,
            server_name,
            connection_type,
            stdio_config,
            http_config,
            auth_config,
        )
    except OSError as e:
        click.echo(style_error(f"Error: Failed to save configuration: {e}"), err=True)
        sys.exit(1)
