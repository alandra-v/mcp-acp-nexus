"""JSON-over-UDS protocol utilities shared by daemon and client.

This module provides the NDJSON (Newline-Delimited JSON) encoding/decoding
used for proxy-manager communication over Unix Domain Sockets.

Protocol format:
- Messages are JSON objects encoded in compact form (no spaces)
- Each message is terminated by a newline character
- Encoding: UTF-8

Message types:
- Proxy → Manager: {"type": "register", "proxy_name": "...", "instance_id": "...", ...}
- Manager → Proxy: {"type": "registered", "ok": true}
- Manager → Proxy: {"type": "ui_status", "browser_connected": bool, "subscriber_count": int}
- Manager → Proxy: {"type": "heartbeat"}
- Manager → Proxy: {"type": "token_update", "access_token": "...", "expires_at": "ISO8601"}
- Proxy → Manager: {"type": "event", "event_type": "...", "data": {...}}

Unknown message types are ignored (forward compatibility).

Example messages:
    {"type":"register","proxy_name":"default","instance_id":"abc123"}\\n
    {"type":"ui_status","browser_connected":true,"subscriber_count":1}\\n
    {"type":"token_update","access_token":"ey...","expires_at":"2024-01-15T12:00:00Z"}\\n
    {"type":"heartbeat"}\\n
"""

from __future__ import annotations

__all__ = [
    "decode_ndjson",
    "encode_ndjson",
]

import json
from typing import Any


def encode_ndjson(msg: dict[str, Any]) -> bytes:
    """Encode a message for NDJSON transmission.

    Uses compact JSON (no spaces after separators) with newline delimiter.

    Args:
        msg: Dictionary to encode.

    Returns:
        UTF-8 encoded bytes with trailing newline.

    Example:
        >>> encode_ndjson({"type": "event", "data": {}})
        b'{"type":"event","data":{}}\\n'
    """
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")


def decode_ndjson(line: bytes) -> dict[str, Any] | None:
    """Decode an NDJSON message.

    Args:
        line: UTF-8 encoded bytes (with or without trailing newline).

    Returns:
        Decoded dictionary, or None if line is empty or contains invalid JSON.

    Example:
        >>> decode_ndjson(b'{"type":"event"}\\n')
        {'type': 'event'}
        >>> decode_ndjson(b'invalid')
        None
    """
    if not line:
        return None
    try:
        result: dict[str, Any] = json.loads(line.decode("utf-8"))
        return result
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
