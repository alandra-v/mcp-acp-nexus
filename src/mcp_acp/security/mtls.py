"""mTLS (Mutual TLS) utilities for secure backend connections.

Provides certificate validation, expiry checking, and httpx client factory
creation for mTLS-authenticated connections to backend servers.
"""

from __future__ import annotations

__all__ = [
    "create_mtls_client_factory",
    "get_certificate_expiry_info",
    "validate_mtls_config",
]

import logging
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from cryptography import x509

from mcp_acp.constants import (
    CERT_EXPIRY_CRITICAL_DAYS,
    CERT_EXPIRY_WARNING_DAYS,
)

if TYPE_CHECKING:
    from mcp.shared._httpx_utils import McpHttpClientFactory

    from mcp_acp.config import MTLSConfig

logger = logging.getLogger(__name__)


# =============================================================================
# mTLS Client Factory
# =============================================================================


def create_mtls_client_factory(
    mtls_config: "MTLSConfig",
) -> "McpHttpClientFactory":
    """Create an httpx client factory with mTLS certificates.

    The returned factory creates httpx.AsyncClient instances configured with
    client certificates for mutual TLS authentication to backend servers.

    Args:
        mtls_config: mTLS configuration with certificate paths.

    Returns:
        Factory callable that creates configured httpx.AsyncClient instances.

    Raises:
        FileNotFoundError: If any certificate file doesn't exist.
        ValueError: If certificates are invalid PEM format.
    """
    # Resolve and validate paths
    cert_path = Path(mtls_config.client_cert_path).expanduser().resolve()
    key_path = Path(mtls_config.client_key_path).expanduser().resolve()
    ca_path = Path(mtls_config.ca_bundle_path).expanduser().resolve()

    # Check files exist
    if not cert_path.exists():
        raise FileNotFoundError(f"mTLS client certificate not found: {cert_path}")
    if not key_path.exists():
        raise FileNotFoundError(f"mTLS client key not found: {key_path}")
    if not ca_path.exists():
        raise FileNotFoundError(f"mTLS CA bundle not found: {ca_path}")

    # Validate certificates are valid PEM format
    _validate_certificates(cert_path, key_path, ca_path)

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
        **kwargs: Any,  # Accept additional args like follow_redirects
    ) -> httpx.AsyncClient:
        """Create httpx client with mTLS certificates.

        This signature matches McpHttpClientFactory Protocol from mcp.shared._httpx_utils.

        Args:
            headers: Optional headers to pass to the client.
            timeout: Optional timeout configuration.
            auth: Optional httpx auth handler.
            **kwargs: Additional arguments passed to httpx.AsyncClient.

        Returns:
            Configured httpx.AsyncClient with mTLS certificates.
        """
        # Create SSL context with CA bundle for server verification
        ssl_context = ssl.create_default_context(cafile=str(ca_path))
        # Load client certificate and key for mTLS
        ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        return httpx.AsyncClient(
            verify=ssl_context,
            headers=headers,
            timeout=timeout,
            auth=auth,
            **kwargs,
        )

    return factory


# =============================================================================
# Certificate Validation
# =============================================================================


def _validate_certificates(cert_path: Path, key_path: Path, ca_path: Path) -> None:
    """Validate certificate files are valid PEM format.

    Creates an SSL context to verify the certificates can be loaded together.
    Also checks certificate expiry and logs warnings if expiring soon.

    Args:
        cert_path: Path to client certificate.
        key_path: Path to client private key.
        ca_path: Path to CA bundle.

    Raises:
        ValueError: If certificates are invalid or don't match.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.load_cert_chain(str(cert_path), str(key_path))
        ctx.load_verify_locations(str(ca_path))
    except ssl.SSLError as e:
        raise ValueError(f"Invalid mTLS certificates: {e}") from e

    # Check certificate expiry
    _check_certificate_expiry(cert_path)


def _check_certificate_expiry(cert_path: Path) -> int | None:
    """Check if certificate is expired or expiring soon.

    Logs a warning if certificate expires within CERT_EXPIRY_WARNING_DAYS.
    Logs a critical warning if expires within CERT_EXPIRY_CRITICAL_DAYS.
    Raises an error if certificate is already expired.

    Args:
        cert_path: Path to certificate file.

    Returns:
        Days until expiry, or None if could not determine.

    Raises:
        ValueError: If certificate is already expired.
    """
    try:
        cert_pem = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        now = datetime.now(timezone.utc)
        expires_at = cert.not_valid_after_utc
        days_until_expiry = (expires_at - now).days

        if days_until_expiry < 0:
            raise ValueError(
                f"mTLS client certificate has expired (expired {-days_until_expiry} days ago). "
                f"Certificate: {cert_path}"
            )

        if days_until_expiry <= CERT_EXPIRY_CRITICAL_DAYS:
            logger.critical(
                "CRITICAL: mTLS client certificate expires in %d days (on %s). "
                "Renew immediately! Certificate: %s",
                days_until_expiry,
                expires_at.strftime("%Y-%m-%d"),
                cert_path,
            )
        elif days_until_expiry <= CERT_EXPIRY_WARNING_DAYS:
            logger.warning(
                "mTLS client certificate expires in %d days (on %s). "
                "Consider renewing soon. Certificate: %s",
                days_until_expiry,
                expires_at.strftime("%Y-%m-%d"),
                cert_path,
            )

        return days_until_expiry
    except ValueError:
        # Re-raise ValueError (our expiry errors)
        raise
    except Exception as e:
        # Log but don't fail for other parsing errors - SSL validation already passed
        logger.warning(
            {
                "event": "certificate_expiry_check_failed",
                "message": f"Could not check certificate expiry for {cert_path}: {e}",
                "component": "mtls",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "details": {"cert_path": str(cert_path)},
            }
        )
        return None


def get_certificate_expiry_info(cert_path: str | Path) -> dict[str, str | int | None]:
    """Get certificate expiry information for display.

    Args:
        cert_path: Path to certificate file.

    Returns:
        Dictionary with expiry info:
        - expires_at: ISO format expiry date
        - days_until_expiry: Days remaining (negative if expired)
        - status: "valid", "warning", "critical", or "expired"
        - error: Error message if parsing failed
    """
    path = Path(cert_path).expanduser().resolve()

    if not path.exists():
        return {"error": f"Certificate not found: {path}"}

    try:
        cert_pem = path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        now = datetime.now(timezone.utc)
        expires_at = cert.not_valid_after_utc
        days_until_expiry = (expires_at - now).days

        if days_until_expiry < 0:
            status = "expired"
        elif days_until_expiry <= CERT_EXPIRY_CRITICAL_DAYS:
            status = "critical"
        elif days_until_expiry <= CERT_EXPIRY_WARNING_DAYS:
            status = "warning"
        else:
            status = "valid"

        return {
            "expires_at": expires_at.isoformat(),
            "days_until_expiry": days_until_expiry,
            "status": status,
        }
    except Exception as e:
        return {"error": str(e)}


def validate_mtls_config(
    cert_path: str,
    key_path: str,
    ca_path: str,
) -> list[str]:
    """Validate mTLS certificate files for user feedback.

    Checks that all files exist, are valid PEM format, and the cert/key match.
    Returns a list of error messages (empty if valid).

    This is designed for use during interactive init to give users helpful feedback.

    Args:
        cert_path: Path to client certificate.
        key_path: Path to client private key.
        ca_path: Path to CA bundle.

    Returns:
        List of error messages. Empty list means all files are valid.
    """
    errors: list[str] = []

    # Resolve paths
    cert = Path(cert_path).expanduser().resolve()
    key = Path(key_path).expanduser().resolve()
    ca = Path(ca_path).expanduser().resolve()

    # Check files exist
    if not cert.exists():
        errors.append(f"Client certificate not found: {cert}")
    if not key.exists():
        errors.append(f"Client private key not found: {key}")
    if not ca.exists():
        errors.append(f"CA bundle not found: {ca}")

    # If any files missing, return early
    if errors:
        return errors

    # Validate PEM format and cert/key match
    try:
        _validate_certificates(cert, key, ca)
    except ValueError as e:
        errors.append(str(e))
        return errors

    # Check expiry
    expiry_info = get_certificate_expiry_info(cert)
    if "error" in expiry_info:
        errors.append(f"Could not check certificate expiry: {expiry_info['error']}")
    elif expiry_info.get("status") == "expired":
        days_value = expiry_info.get("days_until_expiry", 0)
        days = abs(int(days_value)) if days_value is not None else 0
        errors.append(f"Certificate has expired ({days} days ago)")

    return errors
