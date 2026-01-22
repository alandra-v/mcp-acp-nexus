"""Tests for manager-proxy protocol.

Tests the NDJSON protocol used for proxy registration and event forwarding.
"""

from __future__ import annotations

import pytest

from mcp_acp.manager.protocol import (
    PROTOCOL_VERSION,
    decode_ndjson,
    encode_ndjson,
)


class TestEncodeNdjson:
    """Tests for encode_ndjson()."""

    def test_encodes_dict_to_bytes(self) -> None:
        """Encodes a dictionary to UTF-8 bytes."""
        msg = {"type": "register", "proxy_name": "default"}
        result = encode_ndjson(msg)
        assert isinstance(result, bytes)

    def test_ends_with_newline(self) -> None:
        """Encoded message ends with newline."""
        msg = {"type": "event"}
        result = encode_ndjson(msg)
        assert result.endswith(b"\n")

    def test_compact_json_no_spaces(self) -> None:
        """Uses compact JSON format (no spaces after separators)."""
        msg = {"type": "event", "data": {"key": "value"}}
        result = encode_ndjson(msg)
        # Should not contain ": " or ", " - uses ":" and ","
        decoded = result.decode("utf-8").strip()
        assert '": ' not in decoded
        assert '", ' not in decoded

    def test_handles_nested_structures(self) -> None:
        """Handles nested dictionaries and lists."""
        msg = {
            "type": "register",
            "config_summary": {
                "backend": {"transport": "stdio"},
                "tools": ["tool1", "tool2"],
            },
        }
        result = encode_ndjson(msg)
        decoded = decode_ndjson(result)
        assert decoded == msg

    def test_handles_unicode(self) -> None:
        """Handles unicode characters correctly."""
        msg = {"type": "event", "data": {"message": "日本語テスト"}}
        result = encode_ndjson(msg)
        decoded = decode_ndjson(result)
        assert decoded is not None
        assert decoded["data"]["message"] == "日本語テスト"


class TestDecodeNdjson:
    """Tests for decode_ndjson()."""

    def test_decodes_valid_json(self) -> None:
        """Decodes valid JSON bytes to dictionary."""
        line = b'{"type":"event","data":{}}\n'
        result = decode_ndjson(line)
        assert result == {"type": "event", "data": {}}

    def test_handles_missing_newline(self) -> None:
        """Works without trailing newline."""
        line = b'{"type":"event"}'
        result = decode_ndjson(line)
        assert result == {"type": "event"}

    def test_returns_none_for_empty_bytes(self) -> None:
        """Returns None for empty input."""
        assert decode_ndjson(b"") is None

    def test_returns_none_for_invalid_json(self) -> None:
        """Returns None for invalid JSON."""
        assert decode_ndjson(b"not json") is None
        assert decode_ndjson(b"{invalid}") is None
        assert decode_ndjson(b'{"unclosed":') is None

    def test_returns_none_for_invalid_utf8(self) -> None:
        """Returns None for invalid UTF-8."""
        # Invalid UTF-8 sequence
        assert decode_ndjson(b"\xff\xfe") is None

    def test_roundtrip_encode_decode(self) -> None:
        """Encode then decode returns original message."""
        original = {
            "type": "register",
            "protocol_version": PROTOCOL_VERSION,
            "proxy_name": "test-proxy",
            "instance_id": "inst_123",
            "config_summary": {"key": "value"},
        }
        encoded = encode_ndjson(original)
        decoded = decode_ndjson(encoded)
        assert decoded == original


class TestProtocolVersion:
    """Tests for protocol versioning."""

    def test_protocol_version_is_integer(self) -> None:
        """Protocol version is an integer."""
        assert isinstance(PROTOCOL_VERSION, int)

    def test_protocol_version_is_positive(self) -> None:
        """Protocol version is positive."""
        assert PROTOCOL_VERSION > 0
