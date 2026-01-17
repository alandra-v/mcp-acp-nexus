"""Log formatting utilities for JSONL output.

Provides ISO 8601 timestamp formatting for JSONL logs.
All other utilities (payload serialization, metadata extraction, etc.) are in helpers.py.
"""

from __future__ import annotations

__all__ = ["ISO8601Formatter"]

import json
import logging
from datetime import datetime, timezone


class ISO8601Formatter(logging.Formatter):
    """Custom formatter with ISO 8601 timestamps (UTC) for JSONL output.

    Format: YYYY-MM-DDTHH:MM:SS.sssZ
    Example: 2025-12-04T10:48:37.123Z
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSONL with ISO 8601 timestamp.

        Args:
            record: The log record to format

        Returns:
            str: JSON-formatted log entry with timestamp
        """
        # Create ISO 8601 timestamp with milliseconds in UTC
        timestamp = (
            datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

        # Handle dict messages (structured logging)
        if isinstance(record.msg, dict):
            log_data = record.msg
        # Handle JSON string messages (backwards compatibility)
        elif isinstance(record.msg, str) and record.msg.startswith("{"):
            try:
                log_data = json.loads(record.msg)
            except json.JSONDecodeError:
                log_data = {"message": record.msg}
        # Handle plain string/other messages
        else:
            log_data = {"message": str(record.msg)}

        # Add timestamp as first field
        log_entry = {"time": timestamp, **log_data}
        return json.dumps(log_entry)
