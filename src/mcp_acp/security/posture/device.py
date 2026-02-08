"""Device health checks for Zero Trust compliance.

NOTE: This is a basic POC-level implementation, not a comprehensive device
posture solution. Only checks FileVault on/off and SIP on/off on macOS.
A production implementation would include MDM integration, endpoint agents,
certificate-based attestation, etc.

Checks device security posture:
- Disk encryption: FileVault enabled (macOS)
- Device integrity: SIP enabled (macOS)

Both checks are hard gates - proxy won't start if unhealthy.

Design decisions:
- Simple implementation over configurability (MVP/POC)
- No retry logic on individual checks - if command fails, check fails
- Periodic monitoring handles transient failures better than retry
- Only macOS supported; other platforms fail (Zero Trust)

Usage:
    report = check_device_health()
    if not report.is_healthy:
        raise DeviceHealthError(str(report))
"""

from __future__ import annotations

__all__ = [
    "CheckResult",
    "DeviceHealthReport",
    "check_device_health",
]

import platform
import subprocess
from dataclasses import dataclass, field
from typing import Any, Literal

CheckResult = Literal["pass", "fail", "unknown"]

# Timeout for device health check subprocess calls (seconds)
# fdesetup and csrutil are quick local commands - 5 seconds is generous
_SUBPROCESS_TIMEOUT_SECONDS = 5


@dataclass(frozen=True, slots=True)
class DeviceHealthReport:
    """Results of device health checks."""

    disk_encryption: CheckResult
    device_integrity: CheckResult
    platform: str
    errors: list[str] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        """True only if ALL checks passed. Unknown = unhealthy (Zero Trust)."""
        return self.disk_encryption == "pass" and self.device_integrity == "pass"

    def to_dict(self) -> dict[str, Any]:
        """For logging/telemetry."""
        return {
            "disk_encryption": self.disk_encryption,
            "device_integrity": self.device_integrity,
            "platform": self.platform,
            "is_healthy": self.is_healthy,
            "errors": self.errors,
        }

    def __str__(self) -> str:
        status = "HEALTHY" if self.is_healthy else "UNHEALTHY"
        lines = [f"Device Health ({self.platform}): {status}"]
        if self.errors:
            for error in self.errors:
                lines.append(f"  - {error}")
        return "\n".join(lines)


def _check_filevault() -> tuple[CheckResult, str | None]:
    """Check FileVault status. Returns (result, error_message)."""
    try:
        result = subprocess.run(
            ["fdesetup", "status"],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            return "unknown", f"fdesetup exit code {result.returncode}"
        if "FileVault is On" in result.stdout:
            return "pass", None
        if "FileVault is Off" in result.stdout:
            return "fail", "FileVault is disabled"
        return "unknown", f"Unexpected output: {result.stdout.strip()}"
    except subprocess.TimeoutExpired:
        return "unknown", "fdesetup timed out"
    except FileNotFoundError:
        return "unknown", "fdesetup not found"
    except Exception as e:
        return "unknown", f"fdesetup error: {e}"


def _check_sip() -> tuple[CheckResult, str | None]:
    """Check SIP status. Returns (result, error_message)."""
    try:
        result = subprocess.run(
            ["csrutil", "status"],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
        output = result.stdout.lower()
        if "status: enabled" in output:
            return "pass", None
        if "status: disabled" in output:
            return "fail", "SIP is disabled"
        if result.returncode != 0:
            return "unknown", f"csrutil exit code {result.returncode}"
        return "unknown", f"Unexpected output: {result.stdout.strip()}"
    except subprocess.TimeoutExpired:
        return "unknown", "csrutil timed out"
    except FileNotFoundError:
        return "unknown", "csrutil not found"
    except Exception as e:
        return "unknown", f"csrutil error: {e}"


def check_device_health() -> DeviceHealthReport:
    """Run device health checks.

    Returns DeviceHealthReport with results. For Zero Trust:
    - pass = compliant
    - fail = explicitly non-compliant
    - unknown = could not verify (treated as unhealthy)
    """
    current_platform = platform.system()
    errors: list[str] = []

    if current_platform != "Darwin":
        return DeviceHealthReport(
            disk_encryption="fail",
            device_integrity="fail",
            platform=current_platform,
            errors=["Device health checks require macOS"],
        )

    disk_result, disk_error = _check_filevault()
    if disk_error:
        errors.append(disk_error)

    sip_result, sip_error = _check_sip()
    if sip_error:
        errors.append(sip_error)

    return DeviceHealthReport(
        disk_encryption=disk_result,
        device_integrity=sip_result,
        platform=current_platform,
        errors=errors,
    )
