"""Secure credential storage for backend authentication.

Stores backend credentials (API keys, tokens) in the OS keychain
to avoid plaintext storage in config files.

Key format: mcp-acp:proxy:{proxy_name}:backend

Zero Trust: Credentials are never stored in plaintext config files.
Instead, config files contain only a reference key (credential_key).
"""

from __future__ import annotations

__all__ = [
    "BackendCredentialStorage",
    "get_credential_storage",
    "is_keyring_available",
]

from mcp_acp.constants import APP_NAME
from mcp_acp.telemetry.system.system_logger import get_system_logger

# Service name for keyring storage
KEYRING_SERVICE = APP_NAME


class BackendCredentialStorage:
    """Secure storage for backend credentials using OS keychain.

    Stores credentials (API keys, bearer tokens) for HTTP backend servers
    in the system keychain. Config files contain only a reference key,
    not the actual credential.

    Key format: proxy:{proxy_name}:backend

    Usage:
        storage = BackendCredentialStorage("my-proxy")
        storage.save("sk-abc123...")
        credential = storage.load()
    """

    def __init__(self, proxy_name: str) -> None:
        """Initialize credential storage for a proxy.

        Args:
            proxy_name: Name of the proxy (used in keychain key).
        """
        self._proxy_name = proxy_name
        self._service = KEYRING_SERVICE
        self._username = f"proxy:{proxy_name}:backend"

    @property
    def credential_key(self) -> str:
        """Get the credential key for config reference.

        This key is stored in config.json instead of the actual credential.

        Returns:
            Credential key string.
        """
        return self._username

    def save(self, credential: str) -> None:
        """Save credential to keychain.

        Args:
            credential: The credential (API key, token, etc.) to store.

        Raises:
            RuntimeError: If keychain access fails.
        """
        import keyring
        from keyring.errors import KeyringError

        try:
            keyring.set_password(self._service, self._username, credential)
        except KeyringError as e:
            raise RuntimeError(f"Failed to save credential to keychain: {e}") from e

    def load(self) -> str | None:
        """Load credential from keychain.

        Returns:
            The stored credential, or None if not found.

        Raises:
            RuntimeError: If keychain access fails.
        """
        import keyring
        from keyring.errors import KeyringError

        try:
            return keyring.get_password(self._service, self._username)
        except KeyringError as e:
            raise RuntimeError(f"Failed to access keychain: {e}") from e

    def delete(self) -> None:
        """Delete credential from keychain.

        Raises:
            RuntimeError: If keychain access fails.
        """
        import keyring
        from keyring.errors import KeyringError, PasswordDeleteError

        try:
            keyring.delete_password(self._service, self._username)
        except PasswordDeleteError:
            # Credential doesn't exist, that's fine
            pass
        except KeyringError as e:
            raise RuntimeError(f"Failed to delete credential from keychain: {e}") from e

    def exists(self) -> bool:
        """Check if credential exists in keychain.

        Returns:
            True if credential is stored.
        """
        import keyring
        from keyring.errors import KeyringError

        try:
            return keyring.get_password(self._service, self._username) is not None
        except KeyringError:
            return False


def get_credential_storage(proxy_name: str) -> BackendCredentialStorage:
    """Get credential storage for a proxy.

    Args:
        proxy_name: Name of the proxy.

    Returns:
        BackendCredentialStorage instance.
    """
    return BackendCredentialStorage(proxy_name)


def is_keyring_available() -> bool:
    """Check if keyring backend is available and functional.

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
        test_service = f"{APP_NAME}-cred-test"
        test_user = "availability-check"
        test_value = "test"

        keyring.set_password(test_service, test_user, test_value)
        result = keyring.get_password(test_service, test_user)
        keyring.delete_password(test_service, test_user)

        return result == test_value

    except (KeyringError, ImportError) as e:
        logger.debug(
            {
                "event": "keyring_unavailable",
                "reason": "exception",
                "error": str(e),
                "error_type": type(e).__name__,
            }
        )
        return False
