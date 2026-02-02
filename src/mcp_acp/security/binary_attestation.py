"""Binary attestation for STDIO backend verification.

Two complementary verification approaches:

1. **SLSA Provenance** (build-time attestation):
   - Proves binary was built from source in trusted CI/CD pipeline
   - Requires `gh` CLI and GitHub attestation
   - Verify with: `gh attestation verify --owner <owner> <binary>`

2. **Runtime verification** (startup-time):
   - SHA-256 hash verification - confirms binary matches expected
   - Code signature verification (macOS codesign) - tamper detection
   - Post-spawn process path verification - confirms spawned process matches

Design decisions:
- SLSA verification is optional (only when slsa_owner configured)
- Hash verification is optional (only when expected_sha256 configured)
- Code signature verification is macOS-only (codesign -v)
- Process verification is cross-platform (macOS libproc, Linux /proc)
- All configured checks are fail-closed: any failure blocks spawn

Usage:
    # Pre-spawn verification (integrated into transport.py)
    result = verify_backend_binary("/path/to/backend", config)
    if not result.verified:
        raise ProcessVerificationError(result.error)

    # Post-spawn verification (available but NOT integrated)
    verify_spawned_process(process.pid, expected_path="/path/to/backend")

Post-spawn verification integration approach:
    The verify_spawned_process() function is available but NOT currently integrated
    into the transport layer. This is because FastMCP's StdioTransport handles
    process spawning internally in its __aenter__ method.

    To integrate post-spawn verification, you would need to either:

    1. Subclass StdioTransport to add verification after spawn:

        class AttestingStdioTransport(StdioTransport):
            def __init__(self, command, args, expected_path):
                super().__init__(command, args)
                self._expected_path = expected_path

            async def __aenter__(self):
                result = await super().__aenter__()
                # Process is now spawned, verify it
                verify_spawned_process(self._process.pid, self._expected_path)
                return result

    2. Add a hook in LoggingProxyClient.__aenter__ after the transport starts:

        async def __aenter__(self):
            await self._client.__aenter__()
            if isinstance(self._transport, StdioTransport):
                verify_spawned_process(
                    self._transport._process.pid,
                    self._verified_binary_path
                )
            return self

    Note: Pre-spawn verification (hash, signature, SLSA) catches most threats.
    Post-spawn verification is defense-in-depth against process substitution
    attacks that occur between binary verification and process spawn.
"""

from __future__ import annotations

__all__ = [
    "BinaryAttestationConfig",
    "BinaryAttestationResult",
    "verify_backend_binary",
    "verify_spawned_process",
    "verify_spawned_process_async",
]

import asyncio
import ctypes
import hashlib
import hmac
import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from typing import TypedDict

from mcp_acp.exceptions import ProcessVerificationError

logger = logging.getLogger(__name__)

# Timeout for codesign subprocess (seconds)
# codesign -v is quick for local binaries
_CODESIGN_TIMEOUT_SECONDS = 10

# Timeout for gh attestation verify (seconds)
# Network call to GitHub API - allow more time
_GH_ATTESTATION_TIMEOUT_SECONDS = 30

# macOS libproc buffer size (PROC_PIDPATHINFO_MAXSIZE)
_PROC_PIDPATHINFO_MAXSIZE = 4096


# =============================================================================
# TypedDicts for internal helper return types
# =============================================================================


class _SlsaVerificationResult(TypedDict):
    """Result of SLSA provenance verification."""

    valid: bool
    error: str | None


class _CodesignVerificationResult(TypedDict):
    """Result of macOS code signature verification."""

    valid: bool
    error: str | None


@dataclass
class BinaryAttestationConfig:
    """Configuration for binary attestation checks.

    Two verification modes (can use both):

    1. SLSA Provenance (build-time):
       - slsa_owner: GitHub owner (user/org) for `gh attestation verify`
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
            Default True on macOS, ignored on other platforms.
    """

    slsa_owner: str | None = None
    expected_sha256: str | None = None
    require_signature: bool = True


@dataclass(frozen=True, slots=True)
class BinaryAttestationResult:
    """Result of binary attestation verification.

    Immutable result object containing verification status and details.

    Attributes:
        verified: True if all configured checks passed.
        binary_path: Resolved absolute path to the binary.
        sha256: Actual SHA-256 hash of the binary.
        slsa_verified: True if SLSA attestation verified, None if not checked.
        signature_valid: True if code signature verified (macOS), None otherwise.
        error: Error message if verification failed.
    """

    verified: bool
    binary_path: str
    sha256: str | None = None
    slsa_verified: bool | None = None
    signature_valid: bool | None = None
    error: str | None = None


def verify_backend_binary(
    command: str,
    config: BinaryAttestationConfig | None = None,
) -> BinaryAttestationResult:
    """Verify backend binary before spawning.

    Performs configured checks in order:
    1. Resolves command to absolute path via shutil.which()
    2. If slsa_owner set: verifies SLSA provenance via `gh attestation verify`
    3. If expected_sha256 set: verifies binary hash
    4. If require_signature and macOS: verifies code signature

    Args:
        command: Backend command (can be name in PATH or absolute path).
        config: Attestation configuration. If None, uses defaults.

    Returns:
        BinaryAttestationResult with verification status.

    Note:
        This function is synchronous because it runs at startup
        before the async event loop, similar to device health checks.
    """
    if config is None:
        config = BinaryAttestationConfig()

    # Resolve command to absolute path
    binary_path = shutil.which(command)
    if binary_path is None:
        return BinaryAttestationResult(
            verified=False,
            binary_path=command,
            error=f"Binary not found in PATH: {command}",
        )

    # Resolve symlinks to get real path (security: prevent symlink attacks)
    try:
        binary_path = os.path.realpath(binary_path)
    except OSError as e:
        return BinaryAttestationResult(
            verified=False,
            binary_path=command,
            error=f"Failed to resolve binary path: {e}",
        )

    # Compute SHA-256 hash
    try:
        binary_hash = _compute_sha256(binary_path)
    except OSError as e:
        return BinaryAttestationResult(
            verified=False,
            binary_path=binary_path,
            error=f"Failed to read binary for hashing: {e}",
        )

    # SLSA provenance verification (if configured)
    slsa_verified: bool | None = None
    if config.slsa_owner:
        slsa_result = _verify_slsa_provenance(binary_path, config.slsa_owner)
        if not slsa_result["valid"]:
            return BinaryAttestationResult(
                verified=False,
                binary_path=binary_path,
                sha256=binary_hash,
                slsa_verified=False,
                error=slsa_result.get("error", "SLSA provenance verification failed"),
            )
        slsa_verified = True

    # Verify hash if expected_sha256 is configured
    if config.expected_sha256:
        expected = config.expected_sha256.lower().strip()
        if not hmac.compare_digest(binary_hash.lower(), expected):
            return BinaryAttestationResult(
                verified=False,
                binary_path=binary_path,
                sha256=binary_hash,
                slsa_verified=slsa_verified,
                error=f"Hash mismatch: expected {expected}, got {binary_hash}",
            )

    # Code signature verification (macOS only)
    signature_valid: bool | None = None

    if platform.system() == "Darwin":
        if config.require_signature:
            sig_result = _verify_codesign(binary_path)
            if not sig_result["valid"]:
                return BinaryAttestationResult(
                    verified=False,
                    binary_path=binary_path,
                    sha256=binary_hash,
                    slsa_verified=slsa_verified,
                    signature_valid=False,
                    error=sig_result.get("error", "Code signature verification failed"),
                )
            signature_valid = True

    return BinaryAttestationResult(
        verified=True,
        binary_path=binary_path,
        sha256=binary_hash,
        slsa_verified=slsa_verified,
        signature_valid=signature_valid,
    )


def verify_spawned_process(pid: int, expected_path: str) -> None:
    """Verify a spawned process is running the expected binary.

    Checks that the process at the given PID is actually executing
    the expected binary path. This catches process substitution attacks
    where a different binary responds on stdout.

    Args:
        pid: Process ID of the spawned backend.
        expected_path: Expected absolute path of the binary (from verify_backend_binary).

    Raises:
        ProcessVerificationError: If process path doesn't match or can't be verified.

    Note:
        This should be called immediately after subprocess.Popen() or
        asyncio.create_subprocess_exec() before any communication.
    """
    current_platform = platform.system()

    if current_platform == "Darwin":
        actual_path = _get_process_path_macos(pid)
    elif current_platform == "Linux":
        actual_path = _get_process_path_linux(pid)
    else:
        # Windows or other - skip verification with warning
        logger.warning(f"Process verification not supported on {current_platform}, skipping")
        return

    if actual_path is None:
        raise ProcessVerificationError(f"Failed to get executable path for PID {pid}")

    # Resolve both paths to handle symlinks
    try:
        actual_real = os.path.realpath(actual_path)
        expected_real = os.path.realpath(expected_path)
    except OSError as e:
        raise ProcessVerificationError(f"Failed to resolve paths for comparison: {e}") from e

    if actual_real != expected_real:
        raise ProcessVerificationError(
            f"Process path mismatch: PID {pid} running {actual_real}, " f"expected {expected_real}"
        )

    logger.debug(f"Process {pid} verified: {actual_real}")


async def verify_spawned_process_async(pid: int, expected_path: str) -> None:
    """Async wrapper for verify_spawned_process.

    Runs the synchronous verification in a thread pool to avoid
    blocking the event loop.

    Args:
        pid: Process ID of the spawned backend.
        expected_path: Expected absolute path of the binary.

    Raises:
        ProcessVerificationError: If process path doesn't match or can't be verified.

    Note:
        This is NOT currently integrated into the transport layer. The function
        is available for future use when we subclass StdioTransport or add
        a hook after process spawn. See module docstring for integration approach.
    """
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, verify_spawned_process, pid, expected_path)


# =============================================================================
# Internal helpers
# =============================================================================


def _compute_sha256(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        # Read in chunks for large files
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _verify_slsa_provenance(path: str, owner: str) -> _SlsaVerificationResult:
    """Verify SLSA provenance attestation via GitHub CLI.

    Requires `gh` CLI to be installed and authenticated.
    Runs: gh attestation verify --owner <owner> <path>

    Args:
        path: Absolute path to the binary.
        owner: GitHub owner (user or organization) that built the binary.

    Returns:
        Dict with keys:
        - valid: bool - True if attestation verified
        - error: str | None - Error message if verification failed
    """
    # Check if gh CLI is available
    gh_path = shutil.which("gh")
    if gh_path is None:
        return {
            "valid": False,
            "error": "GitHub CLI (gh) not found. Install from https://cli.github.com/",
        }

    try:
        result = subprocess.run(
            ["gh", "attestation", "verify", "--owner", owner, path],
            capture_output=True,
            text=True,
            timeout=_GH_ATTESTATION_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            # Parse error message from stderr
            error_msg = result.stderr.strip() or result.stdout.strip()
            if "no attestations found" in error_msg.lower():
                return {
                    "valid": False,
                    "error": f"No SLSA attestation found for binary from owner '{owner}'",
                }
            if "not logged in" in error_msg.lower() or "authentication" in error_msg.lower():
                return {
                    "valid": False,
                    "error": "GitHub CLI not authenticated. Run 'gh auth login' first.",
                }
            return {"valid": False, "error": error_msg or "SLSA verification failed"}

        logger.debug(f"SLSA provenance verified for {path} (owner: {owner})")
        return {"valid": True, "error": None}

    except subprocess.TimeoutExpired:
        return {"valid": False, "error": "SLSA verification timed out (GitHub API slow?)"}
    except OSError as e:
        return {"valid": False, "error": f"SLSA verification error: {e}"}


def _verify_codesign(path: str) -> _CodesignVerificationResult:
    """Verify code signature on macOS.

    Args:
        path: Absolute path to the binary to verify.

    Returns:
        _CodesignVerificationResult with verification status.
    """
    try:
        result = subprocess.run(
            ["codesign", "-v", "--strict", path],
            capture_output=True,
            text=True,
            timeout=_CODESIGN_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Invalid signature"
            return {"valid": False, "error": error_msg}
    except subprocess.TimeoutExpired:
        return {"valid": False, "error": "codesign verification timed out"}
    except FileNotFoundError:
        return {"valid": False, "error": "codesign command not found"}
    except OSError as e:
        return {"valid": False, "error": f"codesign error: {e}"}

    return {"valid": True, "error": None}


def _get_process_path_macos(pid: int) -> str | None:
    """Get executable path for a process on macOS using libproc."""
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        buf = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
        ret = libproc.proc_pidpath(pid, buf, _PROC_PIDPATHINFO_MAXSIZE)
        if ret <= 0:
            return None
        return buf.value.decode("utf-8")
    except (OSError, ValueError, AttributeError) as e:
        # OSError: library load failure
        # ValueError: decode failure
        # AttributeError: function not found in library
        logger.warning(f"Failed to get process path via libproc: {e}")
        return None


def _get_process_path_linux(pid: int) -> str | None:
    """Get executable path for a process on Linux using /proc."""
    try:
        exe_link = f"/proc/{pid}/exe"
        if not os.path.exists(exe_link):
            return None
        return os.readlink(exe_link)
    except (OSError, PermissionError) as e:
        logger.warning(f"Failed to read /proc/{pid}/exe: {e}")
        return None
