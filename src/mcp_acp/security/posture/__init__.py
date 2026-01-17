"""Device posture checks for Zero Trust compliance.

This module provides:
- Device health checks (disk encryption, SIP)
- Periodic health monitoring with auto-shutdown on failure

"Device posture" is the Zero Trust term for verifying the device
itself is secure enough to be trusted.
"""

from mcp_acp.security.posture.device import (
    CheckResult,
    DeviceHealthReport,
    check_device_health,
)
from mcp_acp.security.posture.device_monitor import (
    DeviceHealthMonitor,
)

__all__ = [
    "CheckResult",
    "DeviceHealthReport",
    "DeviceHealthMonitor",
    "check_device_health",
]
