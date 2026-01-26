"""Secure token storage for OAuth tokens.

Provides two storage backends:
1. KeychainStorage (primary): Uses OS keychain via keyring library
   - macOS: Keychain
   - Windows: Credential Locker
   - Linux: Secret Service (GNOME Keyring, KDE Wallet)

2. EncryptedFileStorage (fallback): Fernet-encrypted file storage
   - Used when keyring is unavailable
   - Key derived from machine-specific identifiers

Zero Trust: Tokens are never stored in plaintext.
"""

from __future__ import annotations

__all__ = [
    "EncryptedFileStorage",
    "KeychainStorage",
    "StoredToken",
    "TokenStorage",
    "create_token_storage",
    "get_token_storage_info",
]

import base64
import hashlib
import platform
import socket
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel

from mcp_acp.constants import APP_NAME, PROTECTED_CONFIG_DIR
from mcp_acp.exceptions import AuthenticationError

if TYPE_CHECKING:
    from cryptography.fernet import Fernet

    from mcp_acp.config import OIDCConfig

# Service name for keyring storage
KEYRING_SERVICE = APP_NAME

# Username key for keyring (single-user design)
KEYRING_USERNAME = "oauth_tokens"

# Encrypted file storage location
ENCRYPTED_TOKEN_FILE = "tokens.enc"


class StoredToken(BaseModel):
    """OAuth tokens stored securely.

    Attributes:
        access_token: JWT access token for API calls.
        refresh_token: Token for obtaining new access tokens.
        id_token: OIDC ID token containing user claims.
        expires_at: UTC timestamp when access_token expires.
        issued_at: UTC timestamp when tokens were issued.
    """

    access_token: str
    refresh_token: str | None = None
    id_token: str | None = None
    expires_at: datetime
    issued_at: datetime

    @property
    def is_expired(self) -> bool:
        """Check if access token has expired."""
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def seconds_until_expiry(self) -> float:
        """Seconds until access token expires (negative if expired)."""
        delta = self.expires_at - datetime.now(timezone.utc)
        return delta.total_seconds()

    def to_json(self) -> str:
        """Serialize to JSON string for storage."""
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> "StoredToken":
        """Deserialize from JSON string."""
        return cls.model_validate_json(data)


class TokenStorage(ABC):
    """Abstract base class for token storage backends."""

    @abstractmethod
    def save(self, token: StoredToken) -> None:
        """Save token to storage.

        Args:
            token: Token to save.

        Raises:
            AuthenticationError: If save fails.
        """

    @abstractmethod
    def load(self) -> StoredToken | None:
        """Load token from storage.

        Returns:
            StoredToken if found, None if no token stored.

        Raises:
            AuthenticationError: If load fails (corruption, decryption error).
        """

    @abstractmethod
    def delete(self) -> None:
        """Delete stored token.

        Raises:
            AuthenticationError: If delete fails.
        """

    @abstractmethod
    def exists(self) -> bool:
        """Check if a token is stored."""


class KeychainStorage(TokenStorage):
    """Token storage using OS keychain via keyring library.

    Uses the system's secure credential storage:
    - macOS: Keychain
    - Windows: Credential Locker
    - Linux: Secret Service API (GNOME Keyring, KDE Wallet, etc.)
    """

    def __init__(self) -> None:
        """Initialize keychain storage."""
        self._service = KEYRING_SERVICE
        self._username = KEYRING_USERNAME

    def save(self, token: StoredToken) -> None:
        """Save token to keychain."""
        import keyring

        try:
            keyring.set_password(self._service, self._username, token.to_json())
        except Exception as e:
            raise AuthenticationError(f"Failed to save token to keychain: {e}") from e

    def load(self) -> StoredToken | None:
        """Load token from keychain."""
        import keyring

        try:
            data = keyring.get_password(self._service, self._username)
        except Exception as e:
            raise AuthenticationError(f"Failed to access keychain: {e}") from e

        if data is None:
            return None

        try:
            return StoredToken.from_json(data)
        except Exception as e:
            raise AuthenticationError(f"Failed to parse stored token (may be corrupted): {e}") from e

    def delete(self) -> None:
        """Delete token from keychain."""
        import keyring
        from keyring.errors import PasswordDeleteError

        try:
            keyring.delete_password(self._service, self._username)
        except PasswordDeleteError:
            # Token doesn't exist, that's fine
            pass
        except Exception as e:
            raise AuthenticationError(f"Failed to delete token from keychain: {e}") from e

    def exists(self) -> bool:
        """Check if token exists in keychain."""
        import keyring

        try:
            return keyring.get_password(self._service, self._username) is not None
        except Exception:
            return False


class EncryptedFileStorage(TokenStorage):
    """Fallback token storage using Fernet-encrypted file.

    Uses symmetric encryption with a key derived from machine-specific
    identifiers. This is less secure than keychain but works when
    keyring is unavailable.

    Key derivation uses:
    - Hostname
    - Machine ID (platform-specific)
    - Static salt for this application

    The encrypted file is stored in the protected config directory.
    """

    def __init__(self) -> None:
        """Initialize encrypted file storage."""
        self._storage_path = Path(PROTECTED_CONFIG_DIR) / ENCRYPTED_TOKEN_FILE
        self._key: bytes | None = None

    def _get_machine_id(self) -> str:
        """Get platform-specific machine identifier.

        Returns:
            String that's unique and stable for this machine.
        """
        system = platform.system()

        if system == "Darwin":  # macOS
            # Use IOPlatformUUID from system_profiler
            try:
                result = subprocess.run(
                    [
                        "ioreg",
                        "-rd1",
                        "-c",
                        "IOPlatformExpertDevice",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for line in result.stdout.split("\n"):
                    if "IOPlatformUUID" in line:
                        # Extract UUID from line like: "IOPlatformUUID" = "..."
                        parts = line.split("=")
                        if len(parts) >= 2:
                            return parts[1].strip().strip('"')
            except (subprocess.SubprocessError, OSError):
                pass

        elif system == "Linux":
            # Try /etc/machine-id (systemd) or /var/lib/dbus/machine-id
            for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                try:
                    with open(path) as f:
                        return f.read().strip()
                except OSError:
                    continue

        elif system == "Windows":
            # Use MachineGuid from registry
            # Note: winreg is Windows-only, mypy can't check it on other platforms
            try:
                winreg = __import__("winreg")
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography",
                    0,
                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
                )
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                return str(value)
            except (OSError, ImportError, AttributeError):
                pass

        # Fallback: hostname (less unique but always available)
        return socket.gethostname()

    def _derive_key(self) -> bytes:
        """Derive encryption key from machine-specific data.

        Uses PBKDF2 with machine ID and hostname as input.

        Returns:
            32-byte key suitable for Fernet.
        """
        if self._key is not None:
            return self._key

        # Combine machine identifiers
        machine_id = self._get_machine_id()
        hostname = socket.gethostname()
        combined = f"{machine_id}:{hostname}:{APP_NAME}-token-storage"

        # Derive key using PBKDF2
        # Note: Salt is static per-application for key stability across restarts.
        # This is acceptable here because:
        # 1. machine_id + hostname provide per-machine uniqueness
        # 2. PBKDF2 with 100k iterations is still computationally expensive
        # 3. Tokens are short-lived (24h access, 30d refresh)
        # 4. This is fallback storage when keychain is unavailable
        # Future enhancement: store random salt in a separate file
        salt = f"{APP_NAME}-v1".encode()
        key = hashlib.pbkdf2_hmac(
            "sha256",
            combined.encode(),
            salt,
            iterations=100_000,
            dklen=32,
        )

        # Fernet requires URL-safe base64 encoded key
        self._key = base64.urlsafe_b64encode(key)
        return self._key

    def _get_fernet(self) -> "Fernet":
        """Get Fernet instance with derived key."""
        from cryptography.fernet import Fernet

        return Fernet(self._derive_key())

    def save(self, token: StoredToken) -> None:
        """Save token to encrypted file."""
        try:
            fernet = self._get_fernet()
            encrypted = fernet.encrypt(token.to_json().encode())

            # Ensure directory exists with secure permissions
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._storage_path.parent.chmod(0o700)

            # Write encrypted data
            self._storage_path.write_bytes(encrypted)
            self._storage_path.chmod(0o600)

        except Exception as e:
            raise AuthenticationError(f"Failed to save encrypted token: {e}") from e

    def load(self) -> StoredToken | None:
        """Load token from encrypted file."""
        if not self._storage_path.exists():
            return None

        try:
            fernet = self._get_fernet()
            encrypted = self._storage_path.read_bytes()
            decrypted = fernet.decrypt(encrypted)
        except Exception as e:
            raise AuthenticationError(
                f"Failed to decrypt token file (may be corrupted or key changed): {e}"
            ) from e

        try:
            return StoredToken.from_json(decrypted.decode())
        except Exception as e:
            raise AuthenticationError(f"Failed to parse stored token (may be corrupted): {e}") from e

    def delete(self) -> None:
        """Delete encrypted token file."""
        try:
            if self._storage_path.exists():
                self._storage_path.unlink()
        except Exception as e:
            raise AuthenticationError(f"Failed to delete encrypted token: {e}") from e

    def exists(self) -> bool:
        """Check if encrypted token file exists."""
        return self._storage_path.exists()


def _is_keyring_available() -> bool:
    """Check if keyring backend is available and functional.

    Returns:
        True if keyring can store/retrieve secrets.
    """
    from mcp_acp.security.keyring_utils import is_keyring_available

    return is_keyring_available(test_service_suffix="token-test")


def create_token_storage(config: "OIDCConfig | None" = None) -> TokenStorage:
    """Create the appropriate token storage backend.

    Prefers keychain storage when available, falls back to encrypted file.

    Args:
        config: OIDC config (reserved for future multi-tenant support).

    Returns:
        TokenStorage instance (KeychainStorage or EncryptedFileStorage).
    """
    if _is_keyring_available():
        return KeychainStorage()
    return EncryptedFileStorage()


def get_token_storage_info() -> dict[str, str]:
    """Get information about the active token storage backend.

    Useful for debugging and status display.

    Returns:
        Dict with 'backend' and 'location' keys.
    """
    if _is_keyring_available():
        import keyring

        backend = keyring.get_keyring()
        return {
            "backend": "keychain",
            "keyring_backend": type(backend).__name__,
            "service": KEYRING_SERVICE,
        }
    return {
        "backend": "encrypted_file",
        "location": str(Path(PROTECTED_CONFIG_DIR) / ENCRYPTED_TOKEN_FILE),
    }
