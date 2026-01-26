"""Interactive prompt helpers for CLI commands.

Provides reusable prompt utilities for gathering user input.
"""

from __future__ import annotations

__all__ = [
    "ProxyAddConfig",
    "confirm_and_edit_loop",
    "parse_comma_separated_args",
    "prompt_auth_config",
    "prompt_http_config",
    "prompt_optional",
    "prompt_stdio_attestation_config",
    "prompt_stdio_config",
    "prompt_with_retry",
]

import platform
from dataclasses import dataclass, field

import click

from mcp_acp.cli.styling import style_error, style_header, style_success
from mcp_acp.config import (
    AuthConfig,
    HttpTransportConfig,
    MTLSConfig,
    OIDCConfig,
    StdioAttestationConfig,
    StdioTransportConfig,
)
from mcp_acp.constants import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    HEALTH_CHECK_TIMEOUT_SECONDS,
    TRANSPORT_TYPE_FROM_INDEX,
    TRANSPORT_TYPE_TO_INDEX,
    TRANSPORT_TYPES,
)
from mcp_acp.utils.transport import check_http_health, validate_mtls_config
from mcp_acp.utils.validation import (
    is_valid_http_url,
    is_valid_oidc_issuer,
    validate_sha256_hex,
)


def _strip_surrounding_quotes(value: str) -> str:
    """Strip matching surrounding quotes from a string.

    Handles both single and double quotes. Only strips if quotes match
    at both ends.

    Examples:
        '"value"' -> 'value'
        "'value'" -> 'value'
        '"value'  -> '"value' (no change, mismatched)
        'value'   -> 'value' (no change, no quotes)
    """
    if len(value) >= 2:
        if (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'"):
            return value[1:-1]
    return value


def parse_comma_separated_args(args_str: str) -> list[str]:
    """Parse comma-separated arguments, stripping whitespace and quotes.

    Users often copy args from JSON examples with quotes included.
    This function strips matching surrounding quotes from each arg.

    Args:
        args_str: Comma-separated string like '-y, "@scope/pkg", /path'

    Returns:
        List of clean args: ['-y', '@scope/pkg', '/path']
    """
    if not args_str:
        return []
    return [_strip_surrounding_quotes(arg.strip()) for arg in args_str.split(",") if arg.strip()]


def prompt_with_retry(prompt_text: str) -> str:
    """Prompt for a required value, retrying if empty.

    Args:
        prompt_text: Text to show in prompt.

    Returns:
        Non-empty string value from user.
    """
    while True:
        value: str = click.prompt(prompt_text, type=str, default="", show_default=False)
        if value.strip():
            return value.strip()
        click.echo("  This field is required.")


def prompt_optional(prompt_text: str, default: str = "") -> str:
    """Prompt for an optional value with default.

    Args:
        prompt_text: Text to show in prompt.
        default: Default value if user presses enter.

    Returns:
        String value from user or default.
    """
    value: str = click.prompt(prompt_text, type=str, default=default, show_default=True)
    return value.strip()


def prompt_stdio_config() -> StdioTransportConfig:
    """Prompt for STDIO transport configuration.

    Returns:
        StdioTransportConfig with user-provided values.
    """
    click.echo()
    click.echo(style_header("STDIO Configuration"))
    command = prompt_with_retry("Command to run")
    args_str = prompt_with_retry("Arguments (comma-separated)")
    args_list = parse_comma_separated_args(args_str)

    # Optional attestation configuration
    attestation_config = prompt_stdio_attestation_config()

    return StdioTransportConfig(command=command, args=args_list, attestation=attestation_config)


def prompt_stdio_attestation_config() -> StdioAttestationConfig | None:
    """Prompt for STDIO binary attestation configuration.

    Returns:
        StdioAttestationConfig if user configures attestation, None otherwise.
    """
    click.echo()
    click.echo(style_header("Binary Attestation (Optional)"))
    click.echo("Attestation verifies the backend binary before spawning.")
    click.echo("Options:")
    click.echo("  - SLSA Provenance: Verify build attestation via GitHub CLI")
    click.echo("  - SHA-256 Hash: Verify binary matches expected hash")
    click.echo("  - Code Signature: Require valid signature (macOS only)")
    click.echo()

    if not click.confirm("Configure binary attestation?", default=False):
        return None

    click.echo()

    # SLSA owner
    click.echo("SLSA Provenance (optional):")
    click.echo("  GitHub owner (user/org) that built the binary.")
    click.echo("  Requires `gh` CLI to be installed and authenticated.")
    slsa_owner = prompt_optional("  SLSA owner (leave empty to skip)")
    slsa_owner = slsa_owner if slsa_owner else None

    # Expected SHA-256
    click.echo("\nSHA-256 Hash (optional):")
    click.echo("  Expected hash of the binary (hex string).")
    click.echo("  Get it with: shasum -a 256 /path/to/binary")
    expected_sha256: str | None = None
    while True:
        sha_input = prompt_optional("  Expected SHA-256 (leave empty to skip)")
        if not sha_input:
            break
        is_valid, normalized = validate_sha256_hex(sha_input)
        if is_valid:
            expected_sha256 = normalized
            break
        click.echo("    Invalid SHA-256 hash. Must be 64 hex characters.")

    # Code signature (macOS only)
    require_signature = False
    if platform.system() == "Darwin":
        click.echo("\nCode Signature (macOS):")
        click.echo("  Require valid code signature from Apple or identified developer.")
        require_signature = click.confirm("  Require code signature?", default=False)

    # Only return config if at least one option is configured
    if not slsa_owner and not expected_sha256 and not require_signature:
        click.echo("\nNo attestation options configured, skipping.")
        return None

    return StdioAttestationConfig(
        slsa_owner=slsa_owner,
        expected_sha256=expected_sha256,
        require_signature=require_signature,
    )


def prompt_http_config() -> HttpTransportConfig:
    """Prompt for HTTP transport configuration and test connectivity.

    Returns:
        HttpTransportConfig with user-provided values.

    Raises:
        click.Abort: If user aborts after connection failure.
    """
    click.echo()
    click.echo(style_header("HTTP Configuration"))

    while True:
        url = prompt_with_retry("Server URL (e.g., https://host:port/mcp)")

        # Validate URL format before proceeding
        if not is_valid_http_url(url):
            click.echo(style_error(f"\nInvalid URL: {url}"))
            click.echo("  URL must start with http:// or https://")
            click.echo("  For STDIO transport (local command), run init again and select STDIO.\n")
            continue

        timeout_str = prompt_optional("Connection timeout (seconds)", str(DEFAULT_HTTP_TIMEOUT_SECONDS))
        try:
            timeout = int(timeout_str)
        except ValueError:
            click.echo(f"  Invalid timeout, using default {DEFAULT_HTTP_TIMEOUT_SECONDS}")
            timeout = DEFAULT_HTTP_TIMEOUT_SECONDS

        # Test connection
        click.echo(f"\nTesting connection to {url}...")
        try:
            check_http_health(url, timeout=min(timeout, HEALTH_CHECK_TIMEOUT_SECONDS))
            click.echo(style_success("Server is reachable!"))
            return HttpTransportConfig(url=url, timeout=timeout)
        except Exception as e:
            error_str = str(e).lower()
            click.echo(f"\nHealth check failed: could not reach {url}")
            click.echo(f"  Error: {e}")
            if "ssl" in error_str or "certificate" in error_str:
                click.echo("\n  Note: SSL/TLS error detected. If this server requires mTLS,")
                click.echo("  you can continue - mTLS will be configured in the next step.")
            click.echo("What would you like to do?")
            click.echo("  1. Continue - server may be offline temporarily")
            click.echo("  2. Reconfigure - enter a different URL")
            click.echo("  3. Cancel - abort setup")
            choice = click.prompt("Select an option", type=click.IntRange(1, 3), default=1)
            if choice == 1:
                return HttpTransportConfig(url=url, timeout=timeout)
            elif choice == 3:
                raise click.Abort()
            # choice == 2: loop continues


def prompt_auth_config(http_config: HttpTransportConfig | None) -> AuthConfig:
    """Prompt for authentication configuration.

    Guides user through OIDC and mTLS configuration with validation.

    Args:
        http_config: HTTP config if using HTTP transport. mTLS prompts
            are only shown for HTTPS backends.

    Returns:
        AuthConfig with user-provided values.
    """
    click.echo()
    click.echo(style_header("Authentication"))
    click.echo("Configure Auth0/OIDC for user authentication.\n")

    # OIDC settings - validate issuer URL format
    while True:
        issuer = prompt_with_retry("OIDC issuer URL (e.g., https://your-tenant.auth0.com)")
        if is_valid_oidc_issuer(issuer):
            break
        click.echo(style_error(f"\nInvalid issuer URL: {issuer}"))
        click.echo("  OIDC issuer must start with https://\n")

    client_id = prompt_with_retry("Auth0 client ID")
    audience = prompt_with_retry("API audience (e.g., https://your-api.example.com)")

    oidc_config = OIDCConfig(
        issuer=issuer,
        client_id=client_id,
        audience=audience,
    )

    # mTLS settings (only for HTTPS backends)
    mtls_config: MTLSConfig | None = None
    if http_config and http_config.url.startswith("https://"):
        click.echo()
        click.echo(style_header("mTLS (Mutual TLS)"))
        click.echo("HTTPS backend detected. mTLS allows the proxy to authenticate")
        click.echo("itself to the backend using a client certificate.\n")
        click.echo("You need 3 PEM files (obtain from your security team):")
        click.echo("  - Client certificate: proves proxy identity to backend")
        click.echo("  - Client private key: must match certificate (keep secure)")
        click.echo("  - CA bundle: verifies backend server's certificate\n")
        click.echo("Skip if your backend doesn't require client certificates.\n")

        if click.confirm("Configure mTLS?", default=False):
            click.echo("\n  (Paths support ~ expansion, e.g., ~/.mcp-certs/client.pem)")

            while True:
                client_cert = prompt_with_retry("Client certificate path")
                client_key = prompt_with_retry("Client private key path")
                ca_bundle = prompt_with_retry("CA bundle path")

                # Validate certificates
                click.echo("\nValidating certificates...")
                errors = validate_mtls_config(client_cert, client_key, ca_bundle)

                if not errors:
                    click.echo("  " + style_success("Certificates valid!"))
                    mtls_config = MTLSConfig(
                        client_cert_path=client_cert,
                        client_key_path=client_key,
                        ca_bundle_path=ca_bundle,
                    )
                    break

                # Show errors
                click.echo("\n  " + style_error("Certificate validation failed:"))
                for error in errors:
                    click.echo(f"    - {error}")
                click.echo()

                # Ask what to do
                choice = click.prompt(
                    "What would you like to do?",
                    type=click.Choice(["retry", "skip", "continue"]),
                    default="retry",
                    show_choices=True,
                )

                if choice == "skip":
                    click.echo("  Skipping mTLS configuration.")
                    break
                elif choice == "continue":
                    click.echo("  Saving config with invalid certificates (will fail at startup).")
                    mtls_config = MTLSConfig(
                        client_cert_path=client_cert,
                        client_key_path=client_key,
                        ca_bundle_path=ca_bundle,
                    )
                    break
                # else retry - loop continues

    click.echo("\nNote: Device health (disk encryption, firewall) is checked at startup.")

    return AuthConfig(
        oidc=oidc_config,
        mtls=mtls_config,
    )


# =============================================================================
# Proxy Add Configuration (for confirmation/edit loop)
# =============================================================================


@dataclass(slots=True)
class ProxyAddConfig:
    """Configuration values collected during proxy add for review/edit.

    This mutable dataclass holds all user-provided values during the
    interactive proxy add flow. Values can be edited before final save.

    Attributes:
        name: Proxy identifier (directory name, must be unique).
        server_name: Backend server display name.
        connection_type: Transport type - "stdio", "http", or "auto".
        command: STDIO command to execute.
        args: STDIO command arguments.
        slsa_owner: GitHub owner for SLSA attestation.
        sha256: Expected SHA-256 hash of binary.
        require_signature: Whether to require code signature (macOS).
        url: HTTP backend URL.
        timeout: HTTP connection timeout in seconds.
        api_key: API key for HTTP backend (stored in keychain).
        mtls_cert: Path to mTLS client certificate.
        mtls_key: Path to mTLS client private key.
        mtls_ca: Path to mTLS CA bundle.
    """

    name: str = ""
    server_name: str = ""
    connection_type: str = "stdio"
    # STDIO
    command: str = ""
    args: list[str] = field(default_factory=list)
    slsa_owner: str = ""
    sha256: str = ""
    require_signature: bool = False
    # HTTP
    url: str = ""
    timeout: int = DEFAULT_HTTP_TIMEOUT_SECONDS
    api_key: str = ""
    # mTLS
    mtls_cert: str = ""
    mtls_key: str = ""
    mtls_ca: str = ""

    def get_editable_fields(self) -> list[tuple[str, str, str]]:
        """Return list of (field_key, label, current_value) for editable fields."""
        fields: list[tuple[str, str, str]] = [
            ("name", "Proxy name", self.name),
            ("server_name", "Server name", self.server_name),
            ("connection_type", "Connection type", self.connection_type),
        ]

        if self.connection_type in ("stdio", "auto"):
            fields.extend(
                [
                    ("command", "Command", self.command),
                    ("args", "Args", ", ".join(self.args) if self.args else "(none)"),
                ]
            )
            # Only show attestation if configured
            if self.slsa_owner or self.sha256 or self.require_signature:
                if self.slsa_owner:
                    fields.append(("slsa_owner", "SLSA owner", self.slsa_owner))
                if self.sha256:
                    fields.append(("sha256", "SHA-256", self.sha256[:16] + "..."))
                if self.require_signature:
                    fields.append(("require_signature", "Require signature", "Yes"))

        if self.connection_type in ("http", "auto"):
            fields.extend(
                [
                    ("url", "URL", self.url),
                    ("timeout", "Timeout", f"{self.timeout}s"),
                ]
            )
            if self.api_key:
                fields.append(("api_key", "API key", "********"))

        # mTLS
        if self.mtls_cert:
            fields.append(("mtls_cert", "mTLS cert", self.mtls_cert))
            fields.append(("mtls_key", "mTLS key", self.mtls_key))
            fields.append(("mtls_ca", "mTLS CA", self.mtls_ca))

        return fields


def _display_config_summary(config: ProxyAddConfig) -> None:
    """Display a summary of the proxy configuration for review."""
    click.echo()
    click.echo(style_header("Review Configuration"))
    click.echo()

    fields = config.get_editable_fields()
    for i, (_, label, value) in enumerate(fields, 1):
        click.echo(f"  {i:2}. {label + ':':<20} {value}")

    click.echo()


def _prompt_for_field(config: ProxyAddConfig, field_key: str) -> None:
    """Re-prompt for a specific field and update config in place.

    Args:
        config: ProxyAddConfig to update.
        field_key: Field identifier from get_editable_fields().

    Note:
        Validates input where appropriate (URL format, SHA-256 format).
        Invalid input shows error and re-prompts.
    """
    if field_key == "name":
        config.name = click.prompt("Proxy name", default=config.name)
    elif field_key == "server_name":
        config.server_name = click.prompt("Server name", default=config.server_name)
    elif field_key == "connection_type":
        click.echo("  [0] stdio - Spawn local process")
        click.echo("  [1] http  - Connect to remote HTTP server")
        click.echo("  [2] auto  - Try HTTP first, fall back to STDIO")
        choice = click.prompt(
            "Select",
            type=click.Choice(["0", "1", "2"] + list(TRANSPORT_TYPES)),
            default=TRANSPORT_TYPE_TO_INDEX.get(config.connection_type, "0"),
        )
        config.connection_type = TRANSPORT_TYPE_FROM_INDEX.get(choice, choice)
    elif field_key == "command":
        config.command = click.prompt("Command", default=config.command)
    elif field_key == "args":
        args_str = click.prompt("Args (comma-separated)", default=", ".join(config.args))
        config.args = parse_comma_separated_args(args_str)
    elif field_key == "url":
        # Validate URL format
        while True:
            url = click.prompt("URL", default=config.url)
            if is_valid_http_url(url):
                config.url = url
                break
            click.echo(style_error("Invalid URL. Must start with http:// or https://"))
    elif field_key == "timeout":
        config.timeout = click.prompt("Timeout (seconds)", default=config.timeout, type=int)
    elif field_key == "api_key":
        config.api_key = click.prompt("API key", default="", hide_input=True)
    elif field_key == "slsa_owner":
        config.slsa_owner = click.prompt("SLSA owner", default=config.slsa_owner)
    elif field_key == "sha256":
        # Validate SHA-256 format
        while True:
            sha = click.prompt("SHA-256 hash (or empty to clear)", default=config.sha256)
            if not sha:
                config.sha256 = ""
                break
            is_valid, normalized = validate_sha256_hex(sha)
            if is_valid:
                config.sha256 = normalized
                break
            click.echo(style_error("Invalid SHA-256. Must be 64 hex characters."))
    elif field_key == "require_signature":
        config.require_signature = click.confirm("Require signature?", default=config.require_signature)
    elif field_key == "mtls_cert":
        config.mtls_cert = click.prompt("mTLS cert path", default=config.mtls_cert)
    elif field_key == "mtls_key":
        config.mtls_key = click.prompt("mTLS key path", default=config.mtls_key)
    elif field_key == "mtls_ca":
        config.mtls_ca = click.prompt("mTLS CA path", default=config.mtls_ca)


def confirm_and_edit_loop(config: ProxyAddConfig) -> bool:
    """Show summary and let user edit fields until confirmed or cancelled.

    Args:
        config: ProxyAddConfig to review and potentially edit.

    Returns:
        True if user confirmed, False if cancelled.
    """
    while True:
        _display_config_summary(config)

        choice = click.prompt(
            "Save this configuration?",
            type=click.Choice(["yes", "edit", "cancel", "y", "e", "c"]),
            default="yes",
            show_choices=True,
        )

        if choice in ("yes", "y"):
            return True
        elif choice in ("cancel", "c"):
            return False
        elif choice in ("edit", "e"):
            fields = config.get_editable_fields()
            field_num = click.prompt(
                f"Edit which field? (1-{len(fields)})",
                type=click.IntRange(1, len(fields)),
            )
            field_key = fields[field_num - 1][0]
            _prompt_for_field(config, field_key)
