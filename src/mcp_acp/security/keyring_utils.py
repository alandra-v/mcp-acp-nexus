"""Shared keyring utility functions.

Provides common keyring operations used by both token_storage and credential_storage.
"""

from __future__ import annotations

__all__ = [
    "is_keyring_available",
]

from mcp_acp.constants import APP_NAME
from mcp_acp.telemetry.system.system_logger import get_system_logger


def is_keyring_available(test_service_suffix: str = "test") -> bool:
    """Check if keyring backend is available and functional.

    Performs a test write/read/delete cycle to verify the keyring
    is working correctly.

    Args:
        test_service_suffix: Suffix for the test service name.
            Default "test" creates "{APP_NAME}-test" service.
            Use different suffixes to avoid test collisions.

    Returns:
        True if keyring can store/retrieve secrets.
    """
    logger = get_system_logger()

    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring
        from keyring.errors import KeyringError

        # Check if we have a real backend (not the fail backend)
        backend = keyring.get_keyring()
        if isinstance(backend, FailKeyring):
            logger.debug(
                {
                    "event": "keyring_unavailable",
                    "reason": "fail_backend",
                    "message": "Keyring using FailKeyring backend (no usable backend found)",
                }
            )
            return False

        # Try a test write/read/delete cycle
        test_service = f"{APP_NAME}-{test_service_suffix}"
        test_user = "availability-check"
        test_value = "test"

        keyring.set_password(test_service, test_user, test_value)
        result = keyring.get_password(test_service, test_user)
        keyring.delete_password(test_service, test_user)

        return result == test_value

    except (KeyringError, ImportError) as e:
        # Known keyring/import errors
        logger.debug(
            {
                "event": "keyring_unavailable",
                "reason": "keyring_error",
                "error": str(e),
                "error_type": type(e).__name__,
            }
        )
        return False
    except Exception as e:
        # Unexpected errors (e.g., DBus errors on Linux, permission issues)
        # Log and return False - keyring availability check should never crash
        logger.debug(
            {
                "event": "keyring_unavailable",
                "reason": "unexpected_error",
                "error": str(e),
                "error_type": type(e).__name__,
            }
        )
        return False
