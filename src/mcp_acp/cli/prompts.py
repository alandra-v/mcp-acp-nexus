"""Interactive prompt helpers for CLI commands.

Provides reusable prompt utilities for gathering user input.
"""

from __future__ import annotations

__all__ = [
    "prompt_auth_config",
    "prompt_http_config",
    "prompt_optional",
    "prompt_stdio_attestation_config",
    "prompt_stdio_config",
    "prompt_with_retry",
]

import platform

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
from mcp_acp.constants import DEFAULT_HTTP_TIMEOUT_SECONDS, HEALTH_CHECK_TIMEOUT_SECONDS
from mcp_acp.utils.transport import check_http_health, validate_mtls_config
from mcp_acp.utils.validation import (
    is_valid_http_url,
    is_valid_oidc_issuer,
    validate_sha256_hex,
)


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
    args_list = [arg.strip() for arg in args_str.split(",") if arg.strip()]

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
