"""Unit tests for API security module.

Tests token management, validation, and security middleware.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_acp.api.security import (
    ALLOWED_HOSTS,
    ALLOWED_ORIGINS,
    AUTH_BYPASS_ENDPOINTS,
    MAX_REQUEST_SIZE,
    SecurityMiddleware,
    generate_token,
    is_valid_token_format,
    validate_token,
)


class TestGenerateToken:
    """Tests for generate_token function."""

    def test_generates_64_char_hex_string(self) -> None:
        """Token is 64 hex characters (32 bytes)."""
        token = generate_token()

        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)

    def test_generates_unique_tokens(self) -> None:
        """Each call generates unique token."""
        tokens = {generate_token() for _ in range(100)}

        assert len(tokens) == 100  # All unique

    def test_token_is_lowercase_hex(self) -> None:
        """Token uses lowercase hex characters."""
        token = generate_token()

        assert token == token.lower()


class TestIsValidTokenFormat:
    """Tests for is_valid_token_format function."""

    def test_valid_token(self) -> None:
        """Given valid 64-char hex token, returns True."""
        token = "a" * 64

        assert is_valid_token_format(token) is True

    def test_rejects_short_token(self) -> None:
        """Given token < 64 chars, returns False."""
        token = "a" * 63

        assert is_valid_token_format(token) is False

    def test_rejects_long_token(self) -> None:
        """Given token > 64 chars, returns False."""
        token = "a" * 65

        assert is_valid_token_format(token) is False

    def test_rejects_non_hex_characters(self) -> None:
        """Given token with non-hex chars, returns False."""
        token = "g" * 64  # 'g' is not hex

        assert is_valid_token_format(token) is False

    def test_rejects_empty_string(self) -> None:
        """Given empty string, returns False."""
        assert is_valid_token_format("") is False

    def test_accepts_uppercase_hex(self) -> None:
        """Given uppercase hex, returns True (case-insensitive)."""
        token = "A" * 64

        assert is_valid_token_format(token) is True

    def test_accepts_mixed_case(self) -> None:
        """Given mixed case hex, returns True."""
        token = "aAbBcCdDeEfF" + "0123456789" * 5 + "ab"

        assert is_valid_token_format(token) is True

    def test_rejects_special_characters(self) -> None:
        """Given token with special chars, returns False."""
        token = "a" * 32 + "<script>" + "a" * 24

        assert is_valid_token_format(token) is False


class TestValidateToken:
    """Tests for validate_token function."""

    def test_matching_tokens_return_true(self) -> None:
        """Given matching tokens, returns True."""
        token = generate_token()

        assert validate_token(token, token) is True

    def test_different_tokens_return_false(self) -> None:
        """Given different tokens, returns False."""
        token1 = generate_token()
        token2 = generate_token()

        assert validate_token(token1, token2) is False

    def test_empty_tokens_match(self) -> None:
        """Given both empty strings, returns True."""
        assert validate_token("", "") is True

    def test_timing_safe_comparison(self) -> None:
        """Validates using hmac.compare_digest (constant time)."""
        # This is more of a behavioral test - the function should not
        # short-circuit on first difference
        token = "a" * 64
        wrong = "b" * 64

        # Both should take similar time (hard to test directly)
        assert validate_token(token, wrong) is False


class TestSecurityMiddlewareHTTP:
    """Tests for SecurityMiddleware with HTTP connections."""

    @pytest.fixture
    def app_with_middleware(self) -> tuple[FastAPI, str]:
        """Create app with security middleware (HTTP mode)."""
        app = FastAPI()
        token = "a" * 64

        @app.get("/api/test")
        async def test_endpoint():
            return {"status": "ok"}

        @app.post("/api/mutate")
        async def mutate_endpoint():
            return {"status": "mutated"}

        @app.get("/api/approvals/pending")
        async def sse_endpoint():
            return {"status": "sse"}

        @app.get("/public")
        async def public_endpoint():
            return {"status": "public"}

        # HTTP mode (is_uds=False is default)
        app.add_middleware(SecurityMiddleware, token=token, is_uds=False)
        return app, token

    @pytest.fixture
    def client(self, app_with_middleware: tuple[FastAPI, str]) -> TestClient:
        """Create test client."""
        app, _ = app_with_middleware
        return TestClient(app, raise_server_exceptions=False)

    def test_rejects_invalid_host(self, client: TestClient) -> None:
        """Given invalid host header, returns 403."""
        response = client.get("/api/test", headers={"host": "evil.com"})

        assert response.status_code == 403
        assert "host" in response.json()["error"].lower()

    def test_accepts_localhost(self, client: TestClient, app_with_middleware: tuple[FastAPI, str]) -> None:
        """Given localhost host header, accepts request."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765", "authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    def test_accepts_127_0_0_1(self, client: TestClient, app_with_middleware: tuple[FastAPI, str]) -> None:
        """Given 127.0.0.1 host header, accepts request."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={"host": "127.0.0.1:8765", "authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    def test_rejects_invalid_origin(
        self, client: TestClient, app_with_middleware: tuple[FastAPI, str]
    ) -> None:
        """Given invalid origin header, returns 403."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={
                "host": "localhost:8765",
                "origin": "http://evil.com",
                "authorization": f"Bearer {token}",
            },
        )

        assert response.status_code == 403
        assert "origin" in response.json()["error"].lower()

    def test_accepts_allowed_origin(
        self, client: TestClient, app_with_middleware: tuple[FastAPI, str]
    ) -> None:
        """Given allowed origin, accepts request."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={
                "host": "localhost:8765",
                "origin": "http://localhost:8765",
                "authorization": f"Bearer {token}",
            },
        )

        assert response.status_code == 200

    def test_requires_auth_for_api_endpoints(self, client: TestClient) -> None:
        """Given no auth header for /api/*, returns 401."""
        response = client.get("/api/test", headers={"host": "localhost:8765"})

        assert response.status_code == 401

    def test_accepts_valid_bearer_token(
        self, client: TestClient, app_with_middleware: tuple[FastAPI, str]
    ) -> None:
        """Given valid bearer token, accepts request."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765", "authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    def test_rejects_invalid_bearer_token(self, client: TestClient) -> None:
        """Given invalid bearer token, returns 401."""
        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765", "authorization": "Bearer wrong-token"},
        )

        assert response.status_code == 401

    def test_accepts_valid_cookie_token(
        self, client: TestClient, app_with_middleware: tuple[FastAPI, str]
    ) -> None:
        """Given valid token in HttpOnly cookie, accepts request."""
        _, token = app_with_middleware

        client.cookies.set("api_token", token)
        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765"},
        )
        client.cookies.clear()

        assert response.status_code == 200

    def test_rejects_invalid_cookie_token(self, client: TestClient) -> None:
        """Given invalid token in cookie, returns 401."""
        client.cookies.set("api_token", "wrong-token")
        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765"},
        )
        client.cookies.clear()

        assert response.status_code == 401

    def test_bearer_token_takes_precedence_over_cookie(
        self, client: TestClient, app_with_middleware: tuple[FastAPI, str]
    ) -> None:
        """Given both bearer token and cookie, bearer token is used."""
        _, token = app_with_middleware

        # Valid bearer, invalid cookie - should succeed (bearer takes precedence)
        client.cookies.set("api_token", "wrong-token")
        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765", "authorization": f"Bearer {token}"},
        )
        client.cookies.clear()

        assert response.status_code == 200

    def test_requires_origin_for_mutations(self, client: TestClient) -> None:
        """Given POST without origin or token, returns 403."""
        response = client.post("/api/mutate", headers={"host": "localhost:8765"})

        assert response.status_code == 403

    def test_allows_mutation_with_valid_token_no_origin(
        self, client: TestClient, app_with_middleware: tuple[FastAPI, str]
    ) -> None:
        """Given POST with valid token but no origin, accepts (CLI access)."""
        _, token = app_with_middleware

        response = client.post(
            "/api/mutate",
            headers={"host": "localhost:8765", "authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    def test_rejects_oversized_request(
        self, client: TestClient, app_with_middleware: tuple[FastAPI, str]
    ) -> None:
        """Given request exceeding size limit, returns 413."""
        _, token = app_with_middleware

        # Create content larger than MAX_REQUEST_SIZE
        response = client.post(
            "/api/mutate",
            headers={
                "host": "localhost:8765",
                "authorization": f"Bearer {token}",
                "content-length": str(MAX_REQUEST_SIZE + 1),
            },
            content=b"x",
        )

        assert response.status_code == 413

    def test_sse_endpoint_same_origin_no_token(self, client: TestClient) -> None:
        """Given SSE endpoint with same-origin (no origin header), accepts."""
        # Same-origin requests don't send Origin header
        response = client.get(
            "/api/approvals/pending",
            headers={"host": "localhost:8765"},
        )

        assert response.status_code == 200

    def test_sse_endpoint_cross_origin_with_token_param(
        self, client: TestClient, app_with_middleware: tuple[FastAPI, str]
    ) -> None:
        """Given SSE endpoint with token query param, accepts."""
        _, token = app_with_middleware

        response = client.get(
            f"/api/approvals/pending?token={token}",
            headers={"host": "localhost:8765", "origin": "http://localhost:3000"},
        )

        assert response.status_code == 200

    def test_adds_security_headers(
        self, client: TestClient, app_with_middleware: tuple[FastAPI, str]
    ) -> None:
        """Response includes security headers."""
        _, token = app_with_middleware

        response = client.get(
            "/api/test",
            headers={"host": "localhost:8765", "authorization": f"Bearer {token}"},
        )

        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers
        assert response.headers["Cache-Control"] == "no-store"

    def test_non_api_endpoints_bypass_auth(self, client: TestClient) -> None:
        """Given non-API endpoint, does not require auth."""
        response = client.get("/public", headers={"host": "localhost:8765"})

        assert response.status_code == 200


class TestSecurityMiddlewareUDS:
    """Tests for SecurityMiddleware with UDS connections.

    UDS connections are pre-authenticated by OS file permissions,
    so token/host/origin validation is skipped.
    """

    @pytest.fixture
    def uds_app_with_middleware(self) -> FastAPI:
        """Create app with security middleware (UDS mode)."""
        app = FastAPI()

        @app.get("/api/test")
        async def test_endpoint():
            return {"status": "ok"}

        @app.post("/api/mutate")
        async def mutate_endpoint():
            return {"status": "mutated"}

        @app.get("/public")
        async def public_endpoint():
            return {"status": "public"}

        # UDS mode - no token needed, OS permissions = auth
        app.add_middleware(SecurityMiddleware, token=None, is_uds=True)
        return app

    @pytest.fixture
    def uds_client(self, uds_app_with_middleware: FastAPI) -> TestClient:
        """Create test client for UDS app."""
        return TestClient(uds_app_with_middleware, raise_server_exceptions=False)

    def test_uds_bypasses_host_validation(self, uds_client: TestClient) -> None:
        """UDS requests skip host header validation."""
        # Invalid host that would fail in HTTP mode
        response = uds_client.get("/api/test", headers={"host": "evil.com"})

        assert response.status_code == 200

    def test_uds_bypasses_origin_validation(self, uds_client: TestClient) -> None:
        """UDS requests skip origin header validation."""
        # Invalid origin that would fail in HTTP mode
        response = uds_client.get(
            "/api/test",
            headers={"host": "localhost", "origin": "http://evil.com"},
        )

        assert response.status_code == 200

    def test_uds_bypasses_token_validation(self, uds_client: TestClient) -> None:
        """UDS requests don't require bearer token."""
        # No Authorization header
        response = uds_client.get("/api/test", headers={"host": "localhost"})

        assert response.status_code == 200

    def test_uds_allows_mutations_without_origin(self, uds_client: TestClient) -> None:
        """UDS POST requests don't require origin header."""
        response = uds_client.post("/api/mutate", headers={"host": "localhost"})

        assert response.status_code == 200

    def test_uds_still_enforces_request_size_limit(self, uds_client: TestClient) -> None:
        """UDS still checks request size limit."""
        response = uds_client.post(
            "/api/mutate",
            headers={
                "host": "localhost",
                "content-length": str(MAX_REQUEST_SIZE + 1),
            },
            content=b"x",
        )

        assert response.status_code == 413

    def test_uds_still_adds_security_headers(self, uds_client: TestClient) -> None:
        """UDS responses still include security headers."""
        response = uds_client.get("/api/test", headers={"host": "localhost"})

        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers

    def test_uds_allows_any_host_header(self, uds_client: TestClient) -> None:
        """UDS accepts any host header (or none)."""
        for host in ["localhost", "127.0.0.1", "evil.com", "", "anything:9999"]:
            response = uds_client.get("/api/test", headers={"host": host})
            assert response.status_code == 200, f"Failed for host: {host}"


class TestAllowedHostsAndOrigins:
    """Tests for security constants."""

    def test_allowed_hosts_includes_localhost_variants(self) -> None:
        """ALLOWED_HOSTS includes common localhost names."""
        assert "localhost" in ALLOWED_HOSTS
        assert "127.0.0.1" in ALLOWED_HOSTS
        assert "[::1]" in ALLOWED_HOSTS

    def test_allowed_origins_includes_production_and_dev(self) -> None:
        """ALLOWED_ORIGINS includes production and dev origins."""
        # Production
        assert "http://localhost:8765" in ALLOWED_ORIGINS
        assert "http://127.0.0.1:8765" in ALLOWED_ORIGINS
        # Development (Vite)
        assert "http://localhost:3000" in ALLOWED_ORIGINS
        assert "http://127.0.0.1:3000" in ALLOWED_ORIGINS

    def test_auth_bypass_endpoints_includes_dev_token(self) -> None:
        """AUTH_BYPASS_ENDPOINTS includes dev-token endpoint."""
        assert "/api/auth/dev-token" in AUTH_BYPASS_ENDPOINTS


class TestAuthBypassEndpoints:
    """Tests for auth bypass endpoints (dev-token)."""

    @pytest.fixture
    def app_with_middleware(self) -> tuple[FastAPI, str]:
        """Create app with security middleware and dev-token bypass."""
        app = FastAPI()
        token = "a" * 64

        @app.get("/api/auth/dev-token")
        async def dev_token_endpoint():
            return {"token": token}

        @app.get("/api/other")
        async def other_endpoint():
            return {"status": "ok"}

        app.add_middleware(SecurityMiddleware, token=token, is_uds=False)
        return app, token

    @pytest.fixture
    def client(self, app_with_middleware: tuple[FastAPI, str]) -> TestClient:
        """Create test client."""
        app, _ = app_with_middleware
        return TestClient(app, raise_server_exceptions=False)

    def test_dev_token_endpoint_bypasses_auth(self, client: TestClient) -> None:
        """Given dev-token endpoint without auth, accepts request."""
        response = client.get(
            "/api/auth/dev-token",
            headers={"host": "localhost:8765"},
        )

        assert response.status_code == 200
        assert "token" in response.json()

    def test_other_api_endpoints_still_require_auth(self, client: TestClient) -> None:
        """Given other /api/* endpoint without auth, returns 401."""
        response = client.get(
            "/api/other",
            headers={"host": "localhost:8765"},
        )

        assert response.status_code == 401

    def test_dev_token_still_validates_host(self, client: TestClient) -> None:
        """Given dev-token with invalid host, returns 403."""
        response = client.get(
            "/api/auth/dev-token",
            headers={"host": "evil.com"},
        )

        assert response.status_code == 403
