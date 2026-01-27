"""API utility modules.

Provides shared utilities for API routes including:
- Log file reading and filtering
- Query parameter definitions for pagination and filtering
"""

from mcp_acp.utils.api.log_reader import (
    build_filters_applied,
    count_entries_and_latest,
    extract_versions,
    get_cutoff_time,
    get_log_base_path,
    parse_comma_separated,
    parse_timestamp,
    read_jsonl_filtered,
)
from mcp_acp.utils.config import LOG_PATHS
from mcp_acp.utils.api.query_params import (
    BeforeQuery,
    LimitQuery,
    time_range_query,
)

__all__ = [
    # From utils.config
    "LOG_PATHS",
    # log_reader.py
    "build_filters_applied",
    "count_entries_and_latest",
    "extract_versions",
    "get_cutoff_time",
    "get_log_base_path",
    "parse_comma_separated",
    "parse_timestamp",
    "read_jsonl_filtered",
    # query_params.py
    "BeforeQuery",
    "LimitQuery",
    "time_range_query",
]
