"""End-to-end integration tests for FastMCP Client through the proxy middleware chain.

Each test uses FastMCP Client with in-memory transport connecting to a proxy
that wraps a test backend. The proxy has the production middleware stack:
Context → Audit (optional) → Enforcement.

Excluded (tested elsewhere):
- HITL (needs async approval coordination)
- Rate limiting (unit-tested in tests/pep/)
- Policy hot-reload (signal-based)
- Manager coordination (tested in tests/manager/)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.client.client import ToolError

from mcp_acp.pdp.policy import PolicyConfig, PolicyRule, RuleConditions
from tests.integration.conftest import create_test_backend, create_test_proxy


# ---------------------------------------------------------------------------
# 1. Discovery bypasses policy
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_list_tools_passes_through(
    integration_client,
    allow_all_policy: PolicyConfig,
) -> None:
    """list_tools() returns all 3 backend tools (discovery bypasses policy)."""
    async with integration_client(allow_all_policy) as client:
        tools = await client.list_tools()
        tool_names = sorted(t.name for t in tools)
        assert tool_names == ["delete_file", "read_file", "write_file"]


# ---------------------------------------------------------------------------
# 2. Allowed tool call
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_allowed_tool_call(integration_client) -> None:
    """call_tool succeeds with an allow rule matching the tool."""
    policy = PolicyConfig(
        rules=[
            PolicyRule(
                id="allow_read",
                effect="allow",
                conditions=RuleConditions(tool_name="read_file"),
            )
        ]
    )
    async with integration_client(policy) as client:
        result = await client.call_tool("read_file", {"path": "/tmp/a"})
        assert result.content[0].text == "contents of /tmp/a"


# ---------------------------------------------------------------------------
# 3. Zero-trust default denies
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_zero_trust_default_denies(
    integration_client,
    deny_all_policy: PolicyConfig,
) -> None:
    """call_tool raises ToolError with empty policy (no rules = deny all)."""
    async with integration_client(deny_all_policy) as client:
        with pytest.raises(ToolError):
            await client.call_tool("read_file", {"path": "/tmp/a"})


# ---------------------------------------------------------------------------
# 4. Explicit deny blocks
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_explicit_deny_blocks(integration_client) -> None:
    """A deny rule blocks a tool even when another allow rule exists."""
    policy = PolicyConfig(
        rules=[
            PolicyRule(
                id="allow_all",
                effect="allow",
                conditions=RuleConditions(tool_name="*"),
            ),
            PolicyRule(
                id="deny_delete",
                effect="deny",
                conditions=RuleConditions(tool_name="delete_file"),
            ),
        ]
    )
    async with integration_client(policy) as client:
        # read_file should be allowed
        result = await client.call_tool("read_file", {"path": "/tmp/a"})
        assert "contents of" in result.content[0].text

        # delete_file should be denied
        with pytest.raises(ToolError):
            await client.call_tool("delete_file", {"path": "/tmp/a"})


# ---------------------------------------------------------------------------
# 5. Allow-all wildcard
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_allow_all_wildcard(
    integration_client,
    allow_all_policy: PolicyConfig,
) -> None:
    """Policy with tool_name='*' allows all tool calls."""
    async with integration_client(allow_all_policy) as client:
        r1 = await client.call_tool("read_file", {"path": "/x"})
        assert "contents of" in r1.content[0].text

        r2 = await client.call_tool("write_file", {"path": "/x", "content": "hi"})
        assert "wrote 2 bytes" in r2.content[0].text

        r3 = await client.call_tool("delete_file", {"path": "/x"})
        assert "deleted" in r3.content[0].text


# ---------------------------------------------------------------------------
# 6. Deny overrides allow (deny-overrides combining)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_deny_overrides_allow(integration_client) -> None:
    """When both allow and deny match, deny wins."""
    policy = PolicyConfig(
        rules=[
            PolicyRule(
                id="allow_write",
                effect="allow",
                conditions=RuleConditions(tool_name="write_file"),
            ),
            PolicyRule(
                id="deny_write",
                effect="deny",
                conditions=RuleConditions(tool_name="write_file"),
            ),
        ]
    )
    async with integration_client(policy) as client:
        with pytest.raises(ToolError):
            await client.call_tool("write_file", {"path": "/tmp/a", "content": "data"})


# ---------------------------------------------------------------------------
# 7. Path-based deny
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_path_based_deny(integration_client) -> None:
    """Allow write_file but deny paths matching /etc/*."""
    policy = PolicyConfig(
        rules=[
            PolicyRule(
                id="allow_write",
                effect="allow",
                conditions=RuleConditions(tool_name="write_file"),
            ),
            PolicyRule(
                id="deny_etc",
                effect="deny",
                conditions=RuleConditions(
                    tool_name="write_file",
                    path_pattern="/etc/*",
                ),
            ),
        ]
    )
    async with integration_client(policy) as client:
        # Writing to /tmp should succeed
        r = await client.call_tool("write_file", {"path": "/tmp/ok", "content": "safe"})
        assert "wrote" in r.content[0].text

        # Writing to /etc should be denied
        with pytest.raises(ToolError):
            await client.call_tool("write_file", {"path": "/etc/passwd", "content": "bad"})


# ---------------------------------------------------------------------------
# 8. Selective tool allow
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_selective_tool_allow(integration_client) -> None:
    """Allow read_file only; write_file and delete_file are denied."""
    policy = PolicyConfig(
        rules=[
            PolicyRule(
                id="allow_read_only",
                effect="allow",
                conditions=RuleConditions(tool_name="read_file"),
            )
        ]
    )
    async with integration_client(policy) as client:
        # read_file allowed
        r = await client.call_tool("read_file", {"path": "/tmp/ok"})
        assert "contents of" in r.content[0].text

        # write_file denied (no matching allow rule)
        with pytest.raises(ToolError):
            await client.call_tool("write_file", {"path": "/tmp/a", "content": "x"})

        # delete_file denied
        with pytest.raises(ToolError):
            await client.call_tool("delete_file", {"path": "/tmp/a"})


# ---------------------------------------------------------------------------
# 9. Audit log records operations
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_audit_log_records_operations(tmp_path: Path) -> None:
    """With log_dir, operations.jsonl gets entries for tool calls."""
    policy = PolicyConfig(
        rules=[
            PolicyRule(
                id="allow_all",
                effect="allow",
                conditions=RuleConditions(tool_name="*"),
            )
        ]
    )
    backend = create_test_backend()
    proxy = create_test_proxy(backend, policy, log_dir=tmp_path)

    async with Client(proxy) as client:
        await client.call_tool("read_file", {"path": "/tmp/a"})
        await client.call_tool("write_file", {"path": "/tmp/b", "content": "hi"})

    # Read operations log
    ops_file = tmp_path / "audit" / "operations.jsonl"
    assert ops_file.exists(), "operations.jsonl should be created"

    entries = [json.loads(line) for line in ops_file.read_text().splitlines() if line.strip()]
    # Filter to tool call operations (exclude list_tools etc.)
    tool_ops = [e for e in entries if e.get("method") == "tools/call"]
    assert len(tool_ops) >= 2, f"Expected at least 2 tool call entries, got {len(tool_ops)}"


# ---------------------------------------------------------------------------
# 10. Audit log records denials
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_audit_log_records_denials(tmp_path: Path) -> None:
    """decisions.jsonl records denied tool calls."""
    policy = PolicyConfig(rules=[])  # deny all
    backend = create_test_backend()
    proxy = create_test_proxy(backend, policy, log_dir=tmp_path)

    async with Client(proxy) as client:
        # Attempt a denied call
        result = await client.call_tool_mcp("read_file", {"path": "/tmp/a"})
        assert result.isError is True

    # Read decisions log
    decisions_file = tmp_path / "audit" / "decisions.jsonl"
    assert decisions_file.exists(), "decisions.jsonl should be created"

    entries = [json.loads(line) for line in decisions_file.read_text().splitlines() if line.strip()]
    deny_entries = [e for e in entries if e.get("decision") == "deny"]
    assert len(deny_entries) >= 1, f"Expected at least 1 deny entry, got {len(deny_entries)}"
