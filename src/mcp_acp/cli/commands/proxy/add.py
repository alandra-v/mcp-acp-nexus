"""Proxy add command."""

from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

import click

from mcp_acp.cli.prompts import ProxyAddConfig, confirm_and_edit_loop, parse_comma_separated_args
from mcp_acp.cli.styling import style_dim, style_error, style_header, style_success, style_warning
from mcp_acp.config import (
    BackendConfig,
    HITLConfig,
    HttpTransportConfig,
    MTLSConfig,
    PerProxyConfig,
    StdioAttestationConfig,
    StdioTransportConfig,
    generate_proxy_id,
    save_proxy_config,
)
from mcp_acp.constants import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    HEALTH_CHECK_TIMEOUT_SECONDS,
    TRANSPORT_TYPE_FROM_INDEX,
    TRANSPORT_TYPES,
)
from mcp_acp.manager.config import (
    find_duplicate_backend,
    get_manager_config_path,
    get_proxy_config_path,
    get_proxy_policy_path,
    load_manager_config,
    validate_proxy_name,
)
from mcp_acp.pdp import create_default_policy
from mcp_acp.utils.policy import save_policy
from mcp_acp.utils.transport import check_http_health
from mcp_acp.utils.validation import validate_sha256_hex


@click.command()
@click.option("--name", "-n", help="Proxy name (will prompt if not provided)")
@click.option("--server-name", help="Backend server name")
@click.option(
    "--connection-type",
    type=click.Choice(TRANSPORT_TYPES),
    help="Connection type: stdio, http, or auto",
)
# STDIO options
@click.option("--command", help="Command to run (for stdio)")
@click.option("--args", help="Command arguments, comma-separated (for stdio)")
@click.option("--attestation-slsa-owner", help="GitHub owner for SLSA attestation (stdio)")
@click.option("--attestation-sha256", help="Expected SHA-256 hash of binary (stdio)")
@click.option(
    "--attestation-require-signature/--no-attestation-require-signature",
    default=None,
    help="Require code signature (macOS only, stdio)",
)
# HTTP options
@click.option("--url", help="Backend URL (for http)")
@click.option(
    "--timeout",
    type=int,
    default=None,
    help=f"HTTP connection timeout in seconds (default: {DEFAULT_HTTP_TIMEOUT_SECONDS})",
)
@click.option("--api-key", help="API key or bearer token for HTTP backend auth (stored in keychain)")
# mTLS options (for HTTPS backends)
@click.option("--mtls-cert", help="Path to client certificate for mTLS (PEM format)")
@click.option("--mtls-key", help="Path to client private key for mTLS (PEM format)")
@click.option("--mtls-ca", help="Path to CA bundle for server verification (PEM format)")
# Confirmation (hidden, for testing/automation)
@click.option("--yes", "-y", is_flag=True, hidden=True, help="Skip confirmation prompt")
def proxy_add(
    name: str | None,
    server_name: str | None,
    connection_type: str | None,
    command: str | None,
    args: str | None,
    attestation_slsa_owner: str | None,
    attestation_sha256: str | None,
    attestation_require_signature: bool | None,
    url: str | None,
    timeout: int | None,
    api_key: str | None,
    mtls_cert: str | None,
    mtls_key: str | None,
    mtls_ca: str | None,
    yes: bool,
) -> None:
    """Add a new proxy configuration.

    Creates a new proxy with backend configuration. OIDC auth settings
    are inherited from manager.json (run 'mcp-acp init' first).
    mTLS is configured per-proxy for HTTPS backends.

    \b
    STDIO Attestation (optional):
    Verify STDIO backend binaries before spawning:
      --attestation-slsa-owner: GitHub owner for SLSA provenance
      --attestation-sha256: Expected SHA-256 hash of binary
      --attestation-require-signature: Require code signature (macOS)

    \b
    mTLS (for HTTPS backends):
    Mutual TLS for secure backend connections:
      --mtls-cert: Path to client certificate (PEM)
      --mtls-key: Path to client private key (PEM)
      --mtls-ca: Path to CA bundle for server verification (PEM)
    """
    # Check prerequisites
    manager_config_path = get_manager_config_path()
    if not manager_config_path.exists():
        click.echo(style_error("Not initialized."))
        click.echo(style_dim("Run 'mcp-acp init' first to set up authentication."))
        raise SystemExit(1)

    # Validate auth is configured
    manager_config = load_manager_config()
    if manager_config.auth is None:
        click.echo(style_error("Auth not configured."))
        click.echo(style_dim("Run 'mcp-acp init --force' to reconfigure with authentication."))
        raise SystemExit(1)

    # Get proxy name
    if not name:
        name = click.prompt("Proxy name", type=str)

    # Validate name
    try:
        validate_proxy_name(name)
    except ValueError as e:
        click.echo(style_error(str(e)))
        raise SystemExit(1)

    # Check not duplicate
    config_path = get_proxy_config_path(name)
    if config_path.exists():
        click.echo(style_error(f"Proxy '{name}' already exists."))
        raise SystemExit(1)

    # Get server name
    if not server_name:
        server_name = click.prompt("Backend server name", type=str)

    # Get connection type
    if not connection_type:
        click.echo()
        click.echo(style_header("Connection Type"))
        click.echo("  [0] stdio - Spawn local process (npx, uvx, python)")
        click.echo("  [1] http  - Connect to remote HTTP/SSE server")
        click.echo("  [2] auto  - Try HTTP first, fall back to STDIO")
        click.echo()

        choice = click.prompt(
            "Select",
            type=click.Choice(["0", "1", "2"] + list(TRANSPORT_TYPES)),
            default="0",
        )
        # Normalize index to name
        connection_type = TRANSPORT_TYPE_FROM_INDEX.get(choice, choice)

    # Build backend config
    stdio_config = None
    http_config = None

    if connection_type in ("stdio", "auto"):
        click.echo()
        click.echo(style_header("STDIO Transport"))
        # Non-interactive if command was provided via flag
        is_interactive = command is None
        stdio_config = _build_stdio_config(
            command=command,
            args=args,
            slsa_owner=attestation_slsa_owner,
            expected_sha256=attestation_sha256,
            require_signature=attestation_require_signature,
            interactive=is_interactive,
        )

    # Track API key for keychain storage (after proxy name is known)
    http_api_key: str | None = None

    if connection_type in ("http", "auto"):
        click.echo()
        click.echo(style_header("HTTP Transport"))
        http_config, http_api_key = _build_http_config(url=url, timeout=timeout, api_key=api_key)

    # Convert connection type to config transport value
    # "http" -> "streamablehttp", others stay the same
    transport = "streamablehttp" if connection_type == "http" else connection_type

    backend_config = BackendConfig(
        server_name=server_name,
        transport=transport,
        stdio=stdio_config,
        http=http_config,
    )

    # Generate proxy ID
    proxy_id = generate_proxy_id(server_name)

    # Build mTLS config if any options provided
    mtls_config: MTLSConfig | None = None
    if mtls_cert or mtls_key or mtls_ca:
        # Require all three if any is provided
        if not (mtls_cert and mtls_key and mtls_ca):
            click.echo(style_error("mTLS requires all three: --mtls-cert, --mtls-key, --mtls-ca"))
            raise SystemExit(1)

        # Validate paths exist
        for path_name, path_val in [("cert", mtls_cert), ("key", mtls_key), ("ca", mtls_ca)]:
            if not Path(path_val).expanduser().exists():
                click.echo(style_error(f"mTLS {path_name} file not found: {path_val}"))
                raise SystemExit(1)

        mtls_config = MTLSConfig(
            client_cert_path=mtls_cert,
            client_key_path=mtls_key,
            ca_bundle_path=mtls_ca,
        )
        click.echo(style_success("mTLS configured for HTTPS backend connections."))

    # Warn about duplicate backend
    if not yes:
        dup_name = find_duplicate_backend(backend_config.stdio, backend_config.http)
        if dup_name:
            click.echo(style_warning(f"Proxy '{dup_name}' already routes to this backend."))
            if not click.confirm("Continue anyway?", default=True):
                raise SystemExit(0)

    # Build ProxyAddConfig for confirmation
    add_config = ProxyAddConfig(
        name=name,
        server_name=server_name,
        connection_type=connection_type,
        command=stdio_config.command if stdio_config else "",
        args=list(stdio_config.args) if stdio_config else [],
        slsa_owner=stdio_config.attestation.slsa_owner if stdio_config and stdio_config.attestation else "",
        sha256=stdio_config.attestation.expected_sha256 if stdio_config and stdio_config.attestation else "",
        require_signature=(
            stdio_config.attestation.require_signature if stdio_config and stdio_config.attestation else False
        ),
        url=http_config.url if http_config else "",
        timeout=http_config.timeout if http_config else DEFAULT_HTTP_TIMEOUT_SECONDS,
        api_key=http_api_key or "",
        mtls_cert=mtls_cert or "",
        mtls_key=mtls_key or "",
        mtls_ca=mtls_ca or "",
    )

    # Confirmation loop (skip with --yes flag)
    if not yes:
        confirmed = confirm_and_edit_loop(add_config)
        if not confirmed:
            click.echo("Cancelled.")
            raise SystemExit(0)

        # Rebuild configs from potentially edited values
        name = add_config.name
        server_name = add_config.server_name

        # Re-validate name if changed
        try:
            validate_proxy_name(name)
        except ValueError as e:
            click.echo(style_error(str(e)))
            raise SystemExit(1)

        # Check not duplicate if name changed
        config_path = get_proxy_config_path(name)
        if config_path.exists():
            click.echo(style_error(f"Proxy '{name}' already exists."))
            raise SystemExit(1)

        # Rebuild STDIO config if needed
        if add_config.connection_type in ("stdio", "auto"):
            attestation = None
            if add_config.slsa_owner or add_config.sha256 or add_config.require_signature:
                attestation = StdioAttestationConfig(
                    slsa_owner=add_config.slsa_owner or None,
                    expected_sha256=add_config.sha256 or None,
                    require_signature=add_config.require_signature,
                )
            stdio_config = StdioTransportConfig(
                command=add_config.command,
                args=add_config.args,
                attestation=attestation,
            )
        else:
            stdio_config = None

        # Rebuild HTTP config if needed
        if add_config.connection_type in ("http", "auto"):
            http_config = HttpTransportConfig(
                url=add_config.url,
                timeout=add_config.timeout,
            )
            http_api_key = add_config.api_key or None
        else:
            http_config = None

        # Convert connection type to config transport value
        transport = "streamablehttp" if add_config.connection_type == "http" else add_config.connection_type

        # Rebuild backend config
        backend_config = BackendConfig(
            server_name=server_name,
            transport=transport,
            stdio=stdio_config,
            http=http_config,
        )

        # Regenerate proxy ID if server name changed
        proxy_id = generate_proxy_id(server_name)

        # Rebuild mTLS config
        mtls_config = None
        if add_config.mtls_cert and add_config.mtls_key and add_config.mtls_ca:
            mtls_config = MTLSConfig(
                client_cert_path=add_config.mtls_cert,
                client_key_path=add_config.mtls_key,
                ca_bundle_path=add_config.mtls_ca,
            )

    # Store API key in keychain if provided
    if http_api_key and http_config is not None:
        from mcp_acp.security.credential_storage import BackendCredentialStorage

        cred_storage = BackendCredentialStorage(name)
        try:
            cred_storage.save(http_api_key)
            # Update configs with credential_key reference using model_copy
            http_config = http_config.model_copy(update={"credential_key": cred_storage.credential_key})
            backend_config = backend_config.model_copy(update={"http": http_config})
            click.echo(style_success("API key stored securely in keychain."))
        except RuntimeError as e:
            click.echo(style_warning(f"Failed to store API key in keychain: {e}"))
            click.echo(style_dim("Continuing without keychain credential storage."))

    # Create config
    proxy_config = PerProxyConfig(
        proxy_id=proxy_id,
        created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        backend=backend_config,
        hitl=HITLConfig(),
        mtls=mtls_config,
    )

    # Save config
    config_path = get_proxy_config_path(name)
    save_proxy_config(name, proxy_config)
    click.echo(style_success(f"Created proxy config: {config_path}"))

    # Create default policy
    policy_path = get_proxy_policy_path(name)
    default_policy = create_default_policy()
    save_policy(default_policy, policy_path)
    click.echo(style_success(f"Created default policy: {policy_path}"))

    click.echo()
    click.echo(style_header("Next Steps"))
    click.echo()

    # Get Claude Desktop config path
    claude_config_path = _get_claude_desktop_config_path()

    # Resolve full path to mcp-acp executable (consistent with install mcp-json)
    executable = shutil.which("mcp-acp")
    executable_path = str(Path(executable).resolve()) if executable else "mcp-acp"

    # Show Claude Desktop config snippet
    click.echo(f"Add to Claude Desktop config ({claude_config_path}):")
    click.echo()
    click.echo(style_dim('  "mcpServers": {'))
    click.echo(style_dim(f'    "{name}": {{'))
    click.echo(style_dim(f'      "command": "{executable_path}",'))
    click.echo(style_dim(f'      "args": ["start", "--proxy", "{name}"]'))
    click.echo(style_dim("    }"))
    click.echo(style_dim("  }"))
    click.echo()
    click.echo(f"Test manually: {style_dim(f'mcp-acp start --proxy {name}')}")


def _build_stdio_config(
    command: str | None,
    args: str | None,
    slsa_owner: str | None,
    expected_sha256: str | None,
    require_signature: bool | None,
    interactive: bool = True,
) -> StdioTransportConfig:
    """Build STDIO transport configuration with interactive prompts.

    Args:
        command: Command to run (prompts if None).
        args: Comma-separated arguments (prompts if None).
        slsa_owner: GitHub owner for SLSA attestation.
        expected_sha256: Expected SHA-256 hash.
        require_signature: Whether to require code signature.
        interactive: Whether to prompt for optional settings (attestation).

    Returns:
        StdioTransportConfig with command, args, and optional attestation.
    """
    import platform

    # Get command
    if not command:
        command = click.prompt("Command to run", type=str)

    # Get args
    args_list: list[str] = []
    if args:
        args_list = parse_comma_separated_args(args)
    elif interactive and click.confirm("Add command arguments?", default=False):
        args_str = click.prompt("Arguments (comma-separated)", type=str, default="")
        if args_str:
            args_list = parse_comma_separated_args(args_str)

    # Build attestation config if any flags provided or user wants to configure
    attestation_config: StdioAttestationConfig | None = None
    has_attestation_flags = slsa_owner or expected_sha256 or require_signature is not None

    if has_attestation_flags:
        # Validate SHA-256 if provided
        if expected_sha256:
            is_valid, normalized = validate_sha256_hex(expected_sha256)
            if not is_valid:
                click.echo(style_error("Invalid --attestation-sha256: must be 64 hex characters"))
                raise SystemExit(1)
            expected_sha256 = normalized

        attestation_config = StdioAttestationConfig(
            slsa_owner=slsa_owner,
            expected_sha256=expected_sha256,
            require_signature=require_signature or False,
        )
        click.echo(style_success("Binary attestation configured."))
    elif interactive and click.confirm("Configure binary attestation?", default=False):
        # Interactive attestation setup
        click.echo()
        click.echo(style_dim("Attestation verifies the backend binary before spawning."))
        click.echo()

        # SLSA owner
        click.echo(style_dim("SLSA Provenance (optional):"))
        click.echo(style_dim("  GitHub owner (user/org) that built the binary."))
        click.echo(style_dim("  Requires `gh` CLI installed and authenticated."))
        slsa_input = click.prompt("  SLSA owner", default="", show_default=False)
        slsa_owner = slsa_input.strip() or None

        # SHA-256
        click.echo()
        click.echo(style_dim("SHA-256 Hash (optional):"))
        click.echo(style_dim("  Get with: shasum -a 256 /path/to/binary"))
        while True:
            sha_input = click.prompt("  Expected SHA-256", default="", show_default=False)
            if not sha_input.strip():
                expected_sha256 = None
                break
            is_valid, normalized = validate_sha256_hex(sha_input)
            if is_valid:
                expected_sha256 = normalized
                break
            click.echo(style_error("  Invalid SHA-256: must be 64 hex characters"))

        # Code signature (macOS only)
        require_signature = False
        if platform.system() == "Darwin":
            click.echo()
            click.echo(style_dim("Code Signature (macOS):"))
            require_signature = click.confirm("  Require valid code signature?", default=False)

        # Only create config if at least one option set
        if slsa_owner or expected_sha256 or require_signature:
            attestation_config = StdioAttestationConfig(
                slsa_owner=slsa_owner,
                expected_sha256=expected_sha256,
                require_signature=require_signature,
            )
            click.echo(style_success("Binary attestation configured."))

    return StdioTransportConfig(
        command=command,
        args=args_list,
        attestation=attestation_config,
    )


def _build_http_config(
    url: str | None,
    timeout: int | None,
    api_key: str | None = None,
) -> tuple[HttpTransportConfig, str | None]:
    """Build HTTP transport configuration with health check.

    Args:
        url: Backend URL (prompts if None).
        timeout: Connection timeout (uses default if None).
        api_key: API key for backend auth (prompts if None and user wants).

    Returns:
        Tuple of (HttpTransportConfig, api_key or None).
        The api_key is returned separately for keychain storage.

    Raises:
        SystemExit: If URL is invalid or user aborts after connection failure.
    """
    # Get URL
    while True:
        if not url:
            url = click.prompt("Backend URL (e.g., https://host:port/mcp)", type=str)

        # Validate URL format
        if not _validate_http_url(url):
            click.echo(style_error(f"Invalid URL: {url}"))
            click.echo(style_dim("URL must start with http:// or https://"))
            if click.confirm("Try a different URL?", default=True):
                url = None
                continue
            raise SystemExit(1)
        break

    # Get timeout
    http_timeout = timeout if timeout is not None else DEFAULT_HTTP_TIMEOUT_SECONDS

    # Test connection
    click.echo(f"Testing connection to {url}...")
    try:
        check_http_health(url, timeout=min(http_timeout, HEALTH_CHECK_TIMEOUT_SECONDS))
        click.echo(style_success("Server is reachable."))
    except (ConnectionError, TimeoutError, OSError) as e:
        error_str = str(e).lower()
        click.echo(style_warning(f"Health check failed: could not reach {url}"))
        click.echo(style_dim(f"  Error: {e}"))
        if "ssl" in error_str or "certificate" in error_str:
            click.echo()
            click.echo(style_dim("  Note: SSL/TLS error detected. If this server requires mTLS,"))
            click.echo(style_dim("  the proxy will use mTLS certs from 'mcp-acp init' at runtime."))

        # Ask what to do
        click.echo()
        click.echo("What would you like to do?")
        click.echo("  1. Continue - server may be offline temporarily")
        click.echo("  2. Reconfigure - enter a different URL")
        click.echo("  3. Cancel - abort proxy creation")
        choice = click.prompt("Select", type=click.IntRange(1, 3), default=1)
        if choice == 2:
            return _build_http_config(url=None, timeout=timeout)
        elif choice == 3:
            raise SystemExit(0)

    # Prompt for API key if not provided and user wants to configure
    if api_key is None:
        click.echo()
        if click.confirm("Configure API key for backend authentication?", default=False):
            api_key = click.prompt(
                "API key (will be stored securely in keychain)",
                type=str,
                hide_input=True,
            )

    # Note: credential_key is set later after we know the proxy name
    return HttpTransportConfig(url=url, timeout=http_timeout), api_key


def _validate_http_url(url: str) -> bool:
    """Validate that a URL is a valid HTTP/HTTPS URL.

    Args:
        url: URL string to validate.

    Returns:
        True if valid, False otherwise.
    """
    url_lower = url.lower().strip()
    if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
        return False
    # Basic check that there's something after the scheme
    scheme_end = url_lower.find("://") + 3
    if len(url_lower) <= scheme_end:
        return False
    return True


def _get_claude_desktop_config_path() -> Path:
    """Get the Claude Desktop config path for the current platform.

    Returns:
        Path to claude_desktop_config.json for macOS, Windows, or Linux.
    """
    import platform

    system = platform.system()
    home = Path.home()

    if system == "Darwin":  # macOS
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        # Use APPDATA on Windows
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        return appdata / "Claude" / "claude_desktop_config.json"
    else:  # Linux and others
        return home / ".config" / "Claude" / "claude_desktop_config.json"
