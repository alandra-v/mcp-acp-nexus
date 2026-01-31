"""Integration test fixtures for FastMCP Client end-to-end proxy tests.

Provides a minimal FastMCP backend, proxy factory with middleware,
and async fixtures for running tests through the full middleware chain.
"""

from __future__ import annotations

import logging
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client, FastMCP

from mcp_acp.config import HITLConfig
from mcp_acp.pdp.policy import PolicyConfig, PolicyRule, RuleConditions
from mcp_acp.pep import create_enforcement_middleware
from mcp_acp.security.identity import LocalIdentityProvider
from mcp_acp.security.shutdown import ShutdownCoordinator
from mcp_acp.telemetry.audit import create_audit_logging_middleware


# ---------------------------------------------------------------------------
# Test backend
# ---------------------------------------------------------------------------


def create_test_backend() -> FastMCP:
    """Create a minimal FastMCP server with 3 known tools."""
    backend = FastMCP("test-backend")

    @backend.tool()
    def read_file(path: str) -> str:
        return f"contents of {path}"

    @backend.tool()
    def write_file(path: str, content: str) -> str:
        return f"wrote {len(content)} bytes to {path}"

    @backend.tool()
    def delete_file(path: str) -> str:
        return f"deleted {path}"

    return backend


# ---------------------------------------------------------------------------
# Proxy factory
# ---------------------------------------------------------------------------


def create_test_proxy(
    backend: FastMCP,
    policy: PolicyConfig,
    *,
    log_dir: Path | None = None,
    protected_dirs: tuple[str, ...] = (),
) -> FastMCP:
    """Create a proxy with the production middleware chain.

    Middleware order (outermost to innermost):
        Audit (optional) → Enforcement

    Note: ContextMiddleware is omitted because it accesses
    ``fastmcp_context.request_id`` during the ``initialize`` handshake,
    which raises ``ValueError`` with in-memory transport. The enforcement
    middleware handles missing context gracefully (falls back to "unknown").

    Args:
        backend: The FastMCP backend server to proxy.
        policy: Policy configuration to enforce.
        log_dir: If provided, enables audit logging middleware.
        protected_dirs: Directories protected from tool access.

    Returns:
        Configured FastMCPProxy with middleware.
    """
    proxy = FastMCP.as_proxy(backend, name="test-proxy")

    identity_provider = LocalIdentityProvider()
    noop_shutdown: Any = lambda reason: None

    # 1. Audit logging middleware (optional, needs log_dir)
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        audit_log_dir = log_dir / "audit"
        audit_log_dir.mkdir(parents=True, exist_ok=True)

        coordinator = ShutdownCoordinator(
            log_dir=log_dir,
            system_logger=logging.getLogger("test.system"),
            proxy_name="test-proxy",
        )
        proxy.add_middleware(
            create_audit_logging_middleware(
                log_path=audit_log_dir / "operations.jsonl",
                shutdown_coordinator=coordinator,
                shutdown_callback=noop_shutdown,
                backend_id="test-backend",
                identity_provider=identity_provider,
                transport="memory",
                log_dir=log_dir,
                proxy_name="test-proxy",
            )
        )

    # 2. Enforcement middleware (innermost)
    enforcement_log_dir = log_dir or Path(tempfile.mkdtemp(prefix="mcp-acp-test-"))
    enforcement_log_dir.mkdir(parents=True, exist_ok=True)
    audit_dir = enforcement_log_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    proxy.add_middleware(
        create_enforcement_middleware(
            policy=policy,
            hitl_config=HITLConfig(),
            protected_dirs=protected_dirs,
            identity_provider=identity_provider,
            backend_id="test-backend",
            log_path=audit_dir / "decisions.jsonl",
            shutdown_callback=noop_shutdown,
            log_dir=enforcement_log_dir,
            proxy_name="test-proxy",
        )
    )

    return proxy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_backend() -> FastMCP:
    """Fresh test backend for each test."""
    return create_test_backend()


@pytest.fixture()
def allow_all_policy() -> PolicyConfig:
    """Policy that allows all tool calls."""
    return PolicyConfig(
        rules=[
            PolicyRule(
                id="allow_all",
                effect="allow",
                conditions=RuleConditions(tool_name="*"),
            )
        ]
    )


@pytest.fixture()
def deny_all_policy() -> PolicyConfig:
    """Policy with no rules (zero-trust default denies everything)."""
    return PolicyConfig(rules=[])


@pytest.fixture()
def integration_client(
    test_backend: FastMCP,
) -> Any:
    """Factory fixture that creates a Client connected to a proxy.

    Usage::

        async with integration_client(policy) as client:
            result = await client.list_tools()
    """
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _factory(
        policy: PolicyConfig,
        *,
        log_dir: Path | None = None,
        protected_dirs: tuple[str, ...] = (),
    ) -> AsyncIterator[Client]:
        proxy = create_test_proxy(
            test_backend,
            policy,
            log_dir=log_dir,
            protected_dirs=protected_dirs,
        )
        async with Client(proxy) as client:
            yield client

    return _factory
