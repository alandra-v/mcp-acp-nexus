"""Unit tests for policy system (PDP).

Tests the policy models, loader, matcher, and engine.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from mcp_acp.context import (
    Action,
    ActionCategory,
    ActionProvenance,
    DecisionContext,
    Environment,
    Provenance,
    Resource,
    ResourceInfo,
    ResourceType,
    ServerInfo,
    Subject,
    SubjectProvenance,
    ToolInfo,
)
from mcp_acp.exceptions import PolicyEnforcementFailure
from mcp_acp.config import HITLConfig
from mcp_acp.pdp import (
    Decision,
    PolicyConfig,
    PolicyEngine,
    PolicyRule,
    RuleConditions,
    create_default_policy,
)
from mcp_acp.utils.policy import (
    create_default_policy_file,
    load_policy,
    policy_exists,
    save_policy,
)
from mcp_acp.pdp.matcher import (
    _match_any,
    _match_operations,
    infer_operation,
    match_path_pattern,
    match_tool_name,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_policy_dir(tmp_path):
    """Create a temporary directory for policy files."""
    return tmp_path


@pytest.fixture
def sample_policy():
    """Create a sample policy with typical rules for testing."""
    return PolicyConfig(
        version="1",
        default_action="deny",
        rules=[
            PolicyRule(
                id="allow-project-read",
                effect="allow",
                conditions=RuleConditions(
                    path_pattern="/project/**",
                    operations=["read"],
                ),
            ),
            PolicyRule(
                id="hitl-project-write",
                effect="hitl",
                conditions=RuleConditions(
                    path_pattern="/project/**",
                    operations=["write"],
                ),
            ),
            PolicyRule(
                id="deny-bash",
                effect="deny",
                conditions=RuleConditions(tool_name="bash"),
            ),
            PolicyRule(
                id="deny-secrets",
                effect="deny",
                conditions=RuleConditions(path_pattern="**/secrets/**"),
            ),
        ],
    )


@pytest.fixture
def make_context():
    """Factory fixture to create DecisionContext for testing.

    Returns a function that builds minimal contexts for policy evaluation tests.
    """

    def _make(
        method: str = "tools/call",
        tool_name: str | None = "test_tool",
        path: str | None = None,
        category: ActionCategory = ActionCategory.ACTION,
        subject_id: str = "testuser",
    ) -> DecisionContext:
        tool = ToolInfo(name=tool_name, provenance=Provenance.MCP_REQUEST) if tool_name else None
        resource_info = ResourceInfo(path=path, provenance=Provenance.MCP_REQUEST) if path else None

        return DecisionContext(
            subject=Subject(
                id=subject_id,
                provenance=SubjectProvenance(id=Provenance.DERIVED),
            ),
            action=Action(
                mcp_method=method,
                name=method.replace("/", "."),
                intent=None,
                category=category,
                provenance=ActionProvenance(intent=None),
            ),
            resource=Resource(
                type=ResourceType.TOOL,
                server=ServerInfo(id="test-server", provenance=Provenance.PROXY_CONFIG),
                tool=tool,
                resource=resource_info,
            ),
            environment=Environment(
                timestamp=datetime.now(timezone.utc),
                request_id="req-123",
                session_id="sess-456",
            ),
        )

    return _make


@pytest.fixture
def deny_bash_policy():
    """Policy that denies bash but allows everything else."""
    return PolicyConfig(
        rules=[
            PolicyRule(effect="deny", conditions=RuleConditions(tool_name="bash")),
            PolicyRule(effect="allow", conditions=RuleConditions(tool_name="*")),
        ]
    )


@pytest.fixture
def path_based_policy():
    """Policy with path-based rules."""
    return PolicyConfig(
        rules=[
            PolicyRule(effect="deny", conditions=RuleConditions(path_pattern="**/secrets/**")),
            PolicyRule(effect="allow", conditions=RuleConditions(path_pattern="/project/**")),
        ]
    )


# ============================================================================
# Tests: PolicyConfig Model
# ============================================================================


class TestPolicyConfigModel:
    """Tests for PolicyConfig model validation."""

    def test_default_version(self):
        """Given no version, defaults to '1'."""
        # Act
        policy = PolicyConfig()

        # Assert
        assert policy.version == "1"

    def test_default_action_is_deny(self):
        """Given no default_action, defaults to 'deny'."""
        # Act
        policy = PolicyConfig()

        # Assert
        assert policy.default_action == "deny"

    def test_default_rules_is_empty_list(self):
        """Given no rules, defaults to empty list."""
        # Act
        policy = PolicyConfig()

        # Assert
        assert policy.rules == []

    def test_is_immutable(self):
        """Given a PolicyConfig, it cannot be modified after creation."""
        # Arrange
        policy = PolicyConfig()

        # Act & Assert
        with pytest.raises(ValidationError):
            policy.version = "2"


# ============================================================================
# Tests: PolicyRule Model
# ============================================================================


class TestRuleIdGeneration:
    """Tests for automatic rule ID generation."""

    def test_auto_generates_id_when_not_provided(self):
        """Given rule without ID, auto-generates deterministic ID."""
        # Act
        policy = PolicyConfig(
            rules=[PolicyRule(effect="allow", conditions=RuleConditions(tool_name="read_*"))]
        )

        # Assert
        assert policy.rules[0].id is not None
        assert policy.rules[0].id.startswith("rule_")
        assert len(policy.rules[0].id) == 13  # "rule_" + 8 hex chars

    def test_preserves_user_provided_id(self):
        """Given rule with user ID, preserves it."""
        # Act
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="my-custom-id",
                    effect="allow",
                    conditions=RuleConditions(tool_name="read_*"),
                )
            ]
        )

        # Assert
        assert policy.rules[0].id == "my-custom-id"

    def test_same_content_generates_same_id(self):
        """Given same rule content, generates same ID (deterministic)."""
        # Act
        policy1 = PolicyConfig(
            rules=[PolicyRule(effect="allow", conditions=RuleConditions(tool_name="read_*"))]
        )
        policy2 = PolicyConfig(
            rules=[PolicyRule(effect="allow", conditions=RuleConditions(tool_name="read_*"))]
        )

        # Assert
        assert policy1.rules[0].id == policy2.rules[0].id

    def test_different_content_generates_different_id(self):
        """Given different rule content, generates different IDs."""
        # Act
        policy1 = PolicyConfig(
            rules=[PolicyRule(effect="allow", conditions=RuleConditions(tool_name="read_*"))]
        )
        policy2 = PolicyConfig(
            rules=[PolicyRule(effect="deny", conditions=RuleConditions(tool_name="read_*"))]
        )

        # Assert
        assert policy1.rules[0].id != policy2.rules[0].id

    def test_mixed_user_and_auto_ids(self):
        """Given mix of user and auto IDs, handles both correctly."""
        # Act
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="user-rule",
                    effect="allow",
                    conditions=RuleConditions(tool_name="a"),
                ),
                PolicyRule(effect="deny", conditions=RuleConditions(tool_name="b")),
            ]
        )

        # Assert
        assert policy.rules[0].id == "user-rule"
        assert policy.rules[1].id.startswith("rule_")

    def test_rejects_duplicate_user_ids(self):
        """Given duplicate user IDs, raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Duplicate rule IDs"):
            PolicyConfig(
                rules=[
                    PolicyRule(
                        id="same-id",
                        effect="allow",
                        conditions=RuleConditions(tool_name="a"),
                    ),
                    PolicyRule(
                        id="same-id",
                        effect="deny",
                        conditions=RuleConditions(tool_name="b"),
                    ),
                ]
            )

    def test_rejects_collision_between_user_and_generated_id(self):
        """Given user ID matching auto-generated ID, raises ValidationError."""
        # First, get the auto-generated ID for a specific rule
        policy = PolicyConfig(rules=[PolicyRule(effect="allow", conditions=RuleConditions(tool_name="test"))])
        generated_id = policy.rules[0].id

        # Now try to create a policy where user provides that same ID for a different rule
        with pytest.raises(ValidationError, match="Rule ID collision"):
            PolicyConfig(
                rules=[
                    PolicyRule(
                        id=generated_id,  # User provides the same ID
                        effect="deny",
                        conditions=RuleConditions(tool_name="other"),
                    ),
                    PolicyRule(
                        effect="allow",
                        conditions=RuleConditions(tool_name="test"),  # Will generate same ID
                    ),
                ]
            )

    def test_id_survives_roundtrip(self, temp_policy_dir):
        """Given policy with auto-generated ID, ID survives save/load."""
        # Arrange
        policy = PolicyConfig(rules=[PolicyRule(effect="allow", conditions=RuleConditions(tool_name="test"))])
        original_id = policy.rules[0].id
        path = temp_policy_dir / "policy.json"

        # Act
        save_policy(policy, path)
        loaded = load_policy(path)

        # Assert
        assert loaded.rules[0].id == original_id


class TestPolicyRuleModel:
    """Tests for PolicyRule model validation."""

    def test_requires_effect_field(self):
        """Given no effect, raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError):
            PolicyRule()

    @pytest.mark.parametrize(
        "effect",
        ["allow", "deny", "hitl"],
        ids=["allow", "deny", "hitl"],
    )
    def test_accepts_valid_effect(self, effect):
        """Given valid effect value, creates rule successfully."""
        # Act
        rule = PolicyRule(effect=effect, conditions=RuleConditions(tool_name="*"))

        # Assert
        assert rule.effect == effect

    def test_rejects_invalid_effect(self):
        """Given invalid effect value, raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError):
            PolicyRule(effect="block", conditions=RuleConditions(tool_name="*"))


# ============================================================================
# Tests: HITLConfig Model
# ============================================================================


class TestHITLConfigModel:
    """Tests for HITLConfig model validation."""

    @pytest.mark.parametrize(
        "timeout",
        [5, 30, 300],
        ids=["minimum", "default", "maximum"],
    )
    def test_accepts_valid_timeout(self, timeout):
        """Given timeout in valid range, creates config successfully."""
        # Act
        config = HITLConfig(timeout_seconds=timeout)

        # Assert
        assert config.timeout_seconds == timeout

    def test_rejects_timeout_below_minimum(self):
        """Given timeout below 5s, raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError):
            HITLConfig(timeout_seconds=4)

    def test_rejects_timeout_above_maximum(self):
        """Given timeout above 300s, raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError):
            HITLConfig(timeout_seconds=301)


# ============================================================================
# Tests: RuleConditions Model
# ============================================================================


class TestRuleConditionsModel:
    """Tests for RuleConditions model validation."""

    def test_requires_at_least_one_condition(self):
        """Given no conditions, raises ValidationError (security risk)."""
        # Act & Assert
        with pytest.raises(ValidationError, match="At least one condition"):
            RuleConditions()

    def test_accepts_single_tool_name_condition(self):
        """Given only tool_name, creates conditions successfully."""
        # Act
        conditions = RuleConditions(tool_name="bash")

        # Assert
        assert conditions.tool_name == "bash"
        assert conditions.path_pattern is None

    def test_accepts_single_path_pattern_condition(self):
        """Given only path_pattern, creates conditions successfully."""
        # Act
        conditions = RuleConditions(path_pattern="/project/**")

        # Assert
        assert conditions.path_pattern == "/project/**"
        assert conditions.tool_name is None

    @pytest.mark.parametrize(
        "operations",
        [["read"], ["write"], ["delete"], ["read", "write", "delete"]],
        ids=["read-only", "write-only", "delete-only", "all-operations"],
    )
    def test_accepts_valid_operations(self, operations):
        """Given valid operation values, creates conditions successfully."""
        # Act
        conditions = RuleConditions(operations=operations)

        # Assert
        assert conditions.operations == operations

    def test_rejects_invalid_operation(self):
        """Given invalid operation value, raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError):
            RuleConditions(operations=["execute"])


# ============================================================================
# Tests: create_default_policy
# ============================================================================


class TestCreateDefaultPolicy:
    """Tests for create_default_policy function."""

    def test_returns_policy_with_deny_default(self):
        """Given no args, returns policy with deny default action."""
        # Act
        policy = create_default_policy()

        # Assert
        assert policy.default_action == "deny"

    def test_returns_policy_with_empty_rules(self):
        """Given no args, returns policy with no rules."""
        # Act
        policy = create_default_policy()

        # Assert
        assert policy.rules == []


# ============================================================================
# Tests: Policy Loader - Save and Load
# ============================================================================


class TestPolicySaveLoad:
    """Tests for policy save and load operations."""

    def test_roundtrip_preserves_version(self, temp_policy_dir, sample_policy):
        """Given saved policy, loading preserves version."""
        # Arrange
        path = temp_policy_dir / "policy.json"

        # Act
        save_policy(sample_policy, path)
        loaded = load_policy(path)

        # Assert
        assert loaded.version == sample_policy.version

    def test_roundtrip_preserves_rule_count(self, temp_policy_dir, sample_policy):
        """Given saved policy, loading preserves rule count."""
        # Arrange
        path = temp_policy_dir / "policy.json"

        # Act
        save_policy(sample_policy, path)
        loaded = load_policy(path)

        # Assert
        assert len(loaded.rules) == len(sample_policy.rules)

    def test_roundtrip_preserves_rule_ids(self, temp_policy_dir, sample_policy):
        """Given saved policy, loading preserves rule IDs."""
        # Arrange
        path = temp_policy_dir / "policy.json"

        # Act
        save_policy(sample_policy, path)
        loaded = load_policy(path)

        # Assert
        assert loaded.rules[0].id == "allow-project-read"

    def test_save_creates_parent_directories(self, temp_policy_dir):
        """Given nested path, save creates parent directories."""
        # Arrange
        path = temp_policy_dir / "nested" / "dir" / "policy.json"
        policy = create_default_policy()

        # Act
        save_policy(policy, path)

        # Assert
        assert path.exists()


# ============================================================================
# Tests: Policy Loader - Error Cases
# ============================================================================


class TestPolicyLoaderErrors:
    """Tests for policy loading error cases."""

    def test_load_missing_file_raises(self, temp_policy_dir):
        """Given nonexistent file, raises FileNotFoundError."""
        # Arrange
        path = temp_policy_dir / "nonexistent.json"

        # Act & Assert
        with pytest.raises(FileNotFoundError):
            load_policy(path)

    def test_load_invalid_json_raises(self, temp_policy_dir):
        """Given malformed JSON, raises ValueError."""
        # Arrange
        path = temp_policy_dir / "invalid.json"
        path.write_text("{ invalid json }")

        # Act & Assert
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_policy(path)

    def test_load_invalid_schema_raises(self, temp_policy_dir):
        """Given invalid schema, raises ValueError."""
        # Arrange
        path = temp_policy_dir / "bad_schema.json"
        path.write_text('{"rules": [{"effect": "invalid"}]}')

        # Act & Assert
        with pytest.raises(ValueError, match="Invalid policy configuration"):
            load_policy(path)


# ============================================================================
# Tests: policy_exists and create_default_policy_file
# ============================================================================


class TestPolicyFileHelpers:
    """Tests for policy file helper functions."""

    def test_policy_exists_returns_false_for_missing(self, temp_policy_dir):
        """Given nonexistent file, returns False."""
        # Arrange
        path = temp_policy_dir / "policy.json"

        # Act & Assert
        assert not policy_exists(path)

    def test_policy_exists_returns_true_for_existing(self, temp_policy_dir, sample_policy):
        """Given existing file, returns True."""
        # Arrange
        path = temp_policy_dir / "policy.json"
        save_policy(sample_policy, path)

        # Act & Assert
        assert policy_exists(path)

    def test_create_default_policy_file_creates_file(self, temp_policy_dir):
        """Given valid path, creates file on disk."""
        # Arrange
        path = temp_policy_dir / "policy.json"

        # Act
        create_default_policy_file(path)

        # Assert
        assert path.exists()

    def test_create_default_policy_file_returns_policy(self, temp_policy_dir):
        """Given valid path, returns created policy."""
        # Arrange
        path = temp_policy_dir / "policy.json"

        # Act
        policy = create_default_policy_file(path)

        # Assert
        assert policy.version == "1"
        assert policy.default_action == "deny"

    def test_create_default_policy_file_raises_if_exists(self, temp_policy_dir, sample_policy):
        """Given existing file, raises FileExistsError."""
        # Arrange
        path = temp_policy_dir / "policy.json"
        save_policy(sample_policy, path)

        # Act & Assert
        with pytest.raises(FileExistsError):
            create_default_policy_file(path)


# ============================================================================
# Tests: Policy Auto-Normalization
# ============================================================================


class TestPolicyAutoNormalization:
    """Tests for auto-normalization of policy files on load.

    When a policy file has rules without IDs, load_policy() should:
    1. Generate IDs in memory (via ensure_rule_ids validator)
    2. Save the normalized policy back to disk (auto-normalization)
    """

    def test_load_generates_missing_ids_in_memory(self, temp_policy_dir):
        """Given policy without rule IDs, loading generates IDs in memory."""
        # Arrange - write policy file without IDs
        path = temp_policy_dir / "policy.json"
        path.write_text(
            """{
            "version": "1",
            "default_action": "deny",
            "rules": [
                {"effect": "allow", "conditions": {"tool_name": "read_file"}}
            ]
        }"""
        )

        # Act
        policy = load_policy(path, normalize=False)

        # Assert - ID was generated in memory
        assert policy.rules[0].id is not None
        assert policy.rules[0].id.startswith("rule_")

    def test_load_auto_saves_when_ids_generated(self, temp_policy_dir):
        """Given policy without rule IDs, loading auto-saves with generated IDs."""
        # Arrange - write policy file without IDs
        path = temp_policy_dir / "policy.json"
        path.write_text(
            """{
            "version": "1",
            "default_action": "deny",
            "rules": [
                {"effect": "allow", "conditions": {"tool_name": "read_file"}}
            ]
        }"""
        )

        # Act - load with normalize=True (default)
        policy = load_policy(path)
        generated_id = policy.rules[0].id

        # Assert - file was updated with generated ID
        import json

        with open(path) as f:
            saved_data = json.load(f)

        assert saved_data["rules"][0]["id"] == generated_id

    def test_load_does_not_save_when_ids_present(self, temp_policy_dir):
        """Given policy with all rule IDs, loading does not modify file."""
        # Arrange - write policy file with IDs
        path = temp_policy_dir / "policy.json"
        original_content = """{
            "version": "1",
            "default_action": "deny",
            "rules": [
                {"id": "my-rule", "effect": "allow", "conditions": {"tool_name": "read_file"}}
            ]
        }"""
        path.write_text(original_content)
        original_mtime = path.stat().st_mtime

        # Act - small delay to ensure mtime would change if file was modified
        import time

        time.sleep(0.01)
        load_policy(path)

        # Assert - file was not modified
        assert path.stat().st_mtime == original_mtime

    def test_load_normalize_false_skips_save(self, temp_policy_dir):
        """Given normalize=False, loading does not save even if IDs generated."""
        # Arrange - write policy file without IDs
        path = temp_policy_dir / "policy.json"
        path.write_text(
            """{
            "version": "1",
            "default_action": "deny",
            "rules": [
                {"effect": "allow", "conditions": {"tool_name": "read_file"}}
            ]
        }"""
        )
        original_mtime = path.stat().st_mtime

        # Act
        import time

        time.sleep(0.01)
        policy = load_policy(path, normalize=False)

        # Assert - IDs generated in memory but file unchanged
        assert policy.rules[0].id is not None
        assert path.stat().st_mtime == original_mtime

    def test_load_normalizes_multiple_rules(self, temp_policy_dir):
        """Given multiple rules without IDs, all get IDs and file is saved."""
        # Arrange
        path = temp_policy_dir / "policy.json"
        path.write_text(
            """{
            "version": "1",
            "default_action": "deny",
            "rules": [
                {"effect": "allow", "conditions": {"tool_name": "read_file"}},
                {"effect": "deny", "conditions": {"tool_name": "bash"}},
                {"id": "existing-id", "effect": "hitl", "conditions": {"path_pattern": "/tmp/**"}}
            ]
        }"""
        )

        # Act
        policy = load_policy(path)

        # Assert - first two rules got generated IDs, third preserved
        assert policy.rules[0].id is not None
        assert policy.rules[0].id.startswith("rule_")
        assert policy.rules[1].id is not None
        assert policy.rules[1].id.startswith("rule_")
        assert policy.rules[2].id == "existing-id"

        # Verify file was saved with all IDs
        import json

        with open(path) as f:
            saved_data = json.load(f)

        assert saved_data["rules"][0]["id"] == policy.rules[0].id
        assert saved_data["rules"][1]["id"] == policy.rules[1].id
        assert saved_data["rules"][2]["id"] == "existing-id"

    def test_load_normalization_is_idempotent(self, temp_policy_dir):
        """Given normalized file, subsequent loads don't modify it."""
        # Arrange - create file without IDs
        path = temp_policy_dir / "policy.json"
        path.write_text(
            """{
            "version": "1",
            "default_action": "deny",
            "rules": [
                {"effect": "allow", "conditions": {"tool_name": "read_file"}}
            ]
        }"""
        )

        # Act - first load normalizes
        policy1 = load_policy(path)
        mtime_after_first = path.stat().st_mtime

        # Second load should not modify
        import time

        time.sleep(0.01)
        policy2 = load_policy(path)

        # Assert - same ID, file unchanged on second load
        assert policy1.rules[0].id == policy2.rules[0].id
        assert path.stat().st_mtime == mtime_after_first

    def test_load_normalization_failure_logs_warning(self, temp_policy_dir, caplog, monkeypatch):
        """Given save failure during normalization, logs warning and returns policy."""
        import logging

        from mcp_acp.utils.policy import policy_helpers

        # Arrange - write policy file without IDs
        path = temp_policy_dir / "policy.json"
        path.write_text(
            """{
            "version": "1",
            "default_action": "deny",
            "rules": [
                {"effect": "allow", "conditions": {"tool_name": "read_file"}}
            ]
        }"""
        )

        # Mock save_policy to raise OSError
        def mock_save_policy(*args, **kwargs):
            raise OSError("Mocked permission denied")

        monkeypatch.setattr(policy_helpers, "save_policy", mock_save_policy)

        # Act - load should succeed despite save failure
        with caplog.at_level(logging.WARNING):
            policy = load_policy(path)

        # Assert - policy is valid
        assert policy.rules[0].id is not None
        assert policy.rules[0].id.startswith("rule_")

        # Assert - warning was logged
        assert any("Failed to save normalized policy" in r.message for r in caplog.records)


# ============================================================================
# Tests: Pattern Matcher - Path Patterns
# ============================================================================


class TestMatchPathPattern:
    """Tests for path pattern matching."""

    @pytest.mark.parametrize(
        ("pattern", "path", "expected"),
        [
            # ** matches anything including / (and the directory itself)
            ("/project/**", "/project", True),  # Directory itself
            ("/project/**", "/project/", True),  # Directory with trailing slash
            ("/project/**", "/project/src/main.py", True),
            ("/project/**", "/project/deep/nested/file.txt", True),
            ("/project/**", "/other/file.txt", False),
            ("/project/**", "/projectX", False),  # Similar prefix but different
            # * matches anything except /
            ("/project/*", "/project/file.txt", True),
            ("/project/*", "/project/src/file.txt", False),
            # Specific patterns
            ("**/*.key", "/home/user/secrets.key", True),
            ("**/*.key", "/secrets.key", True),
            ("**/*.key", "/home/user/secrets.txt", False),
            ("**/secrets/**", "/app/secrets/token.txt", True),
            ("**/secrets/**", "/secrets/key", True),
            ("**/secrets/**", "/app/config/token.txt", False),
            # ? matches single character
            ("/tmp/file?.txt", "/tmp/file1.txt", True),
            ("/tmp/file?.txt", "/tmp/file12.txt", False),
            # Exact match
            ("/etc/passwd", "/etc/passwd", True),
            ("/etc/passwd", "/etc/shadow", False),
            # Edge cases
            ("**", "/any/path/at/all", True),
            ("*", "file.txt", True),
            ("*", "path/file.txt", False),
        ],
        ids=[
            "double-star-matches-dir-itself",
            "double-star-matches-dir-trailing-slash",
            "double-star-deep",
            "double-star-deeper",
            "double-star-no-match",
            "double-star-rejects-similar-prefix",
            "single-star-match",
            "single-star-no-nested",
            "extension-deep",
            "extension-root",
            "extension-no-match",
            "secrets-nested",
            "secrets-shallow",
            "secrets-no-match",
            "question-single",
            "question-multiple",
            "exact-match",
            "exact-no-match",
            "double-star-only",
            "star-no-slash",
            "star-with-slash",
        ],
    )
    def test_pattern_matching(self, pattern, path, expected):
        """Given pattern and path, returns expected match result."""
        # Act & Assert
        assert match_path_pattern(pattern, path) == expected

    def test_none_path_never_matches(self):
        """Given None path, returns False regardless of pattern."""
        # Act & Assert
        assert match_path_pattern("/project/**", None) is False


# ============================================================================
# Tests: Source/Dest Path Conditions
# ============================================================================


class TestSourceDestPathConditions:
    """Tests for source_path and dest_path condition matching."""

    def test_source_path_condition_matches(self):
        """Given source_path condition, matches source path in context."""
        # Arrange
        rule = PolicyRule(
            effect="deny",
            conditions=RuleConditions(source_path="/secrets/**"),
        )
        policy = PolicyConfig(rules=[rule])
        engine = PolicyEngine(policy)

        context = _make_context_with_paths(
            source_path="/secrets/key.pem",
            dest_path="/tmp/key.pem",
        )

        # Act
        decision = engine.evaluate(context)

        # Assert
        assert decision == Decision.DENY

    def test_dest_path_condition_matches(self):
        """Given dest_path condition, matches destination path in context."""
        # Arrange
        rule = PolicyRule(
            effect="deny",
            conditions=RuleConditions(dest_path="/secrets/**"),
        )
        policy = PolicyConfig(rules=[rule])
        engine = PolicyEngine(policy)

        context = _make_context_with_paths(
            source_path="/tmp/key.pem",
            dest_path="/secrets/key.pem",
        )

        # Act
        decision = engine.evaluate(context)

        # Assert
        assert decision == Decision.DENY

    def test_source_and_dest_both_must_match(self):
        """Given both source_path and dest_path conditions, both must match (AND)."""
        # Arrange
        rule = PolicyRule(
            effect="allow",
            conditions=RuleConditions(
                source_path="/tmp/**",
                dest_path="/project/**",
            ),
        )
        policy = PolicyConfig(rules=[rule])
        engine = PolicyEngine(policy)

        # Context where both match
        context_match = _make_context_with_paths(
            source_path="/tmp/file.txt",
            dest_path="/project/file.txt",
        )

        # Context where only source matches
        context_no_match = _make_context_with_paths(
            source_path="/tmp/file.txt",
            dest_path="/secrets/file.txt",
        )

        # Act & Assert
        assert engine.evaluate(context_match) == Decision.ALLOW
        assert engine.evaluate(context_no_match) == Decision.DENY  # default

    def test_source_path_none_does_not_match(self):
        """Given source_path condition but no source in context, no match."""
        # Arrange
        rule = PolicyRule(
            effect="allow",
            conditions=RuleConditions(source_path="/tmp/**"),
        )
        policy = PolicyConfig(rules=[rule])
        engine = PolicyEngine(policy)

        # Context with only path, no source_path
        context = _make_context_with_paths(path="/tmp/file.txt")

        # Act
        decision = engine.evaluate(context)

        # Assert - should be DENY (default) since source_path condition not matched
        assert decision == Decision.DENY


def _make_context_with_paths(
    *,
    path: str | None = None,
    source_path: str | None = None,
    dest_path: str | None = None,
) -> DecisionContext:
    """Helper to create a DecisionContext with specific paths."""
    from mcp_acp.context import (
        Action,
        ActionCategory,
        ActionProvenance,
        Environment,
        Provenance,
        Resource,
        ResourceInfo,
        ResourceType,
        ServerInfo,
        Subject,
        SubjectProvenance,
        ToolInfo,
    )
    from datetime import datetime, timezone

    return DecisionContext(
        subject=Subject(
            id="test_user",
            provenance=SubjectProvenance(id=Provenance.DERIVED),
        ),
        action=Action(
            mcp_method="tools/call",
            name="tools.call",
            intent=None,
            category=ActionCategory.ACTION,
            provenance=ActionProvenance(),
        ),
        resource=Resource(
            type=ResourceType.TOOL,
            server=ServerInfo(id="test-server", provenance=Provenance.PROXY_CONFIG),
            tool=ToolInfo(name="move_file", provenance=Provenance.MCP_REQUEST),
            resource=ResourceInfo(
                path=path or source_path,
                source_path=source_path,
                dest_path=dest_path,
                provenance=Provenance.MCP_REQUEST,
            ),
        ),
        environment=Environment(
            timestamp=datetime.now(timezone.utc),
            request_id="test-req",
            session_id="test-session",
        ),
    )


# ============================================================================
# Tests: Pattern Matcher - Tool Names
# ============================================================================


class TestMatchToolName:
    """Tests for tool name pattern matching."""

    @pytest.mark.parametrize(
        ("pattern", "name", "expected"),
        [
            ("bash", "bash", True),
            ("bash", "zsh", False),
            ("*_file", "read_file", True),
            ("*_file", "write_file", True),
            ("*_file", "execute", False),
            ("read_*", "read_file", True),
            ("read_*", "write_file", False),
            ("execute_*", "execute_command", True),
        ],
        ids=[
            "exact-match",
            "exact-no-match",
            "suffix-read",
            "suffix-write",
            "suffix-no-match",
            "prefix-read",
            "prefix-no-match",
            "prefix-execute",
        ],
    )
    def test_pattern_matching(self, pattern, name, expected):
        """Given pattern and tool name, returns expected match result."""
        # Act & Assert
        assert match_tool_name(pattern, name) == expected

    def test_none_name_never_matches(self):
        """Given None name, returns False regardless of pattern."""
        # Act & Assert
        assert match_tool_name("bash", None) is False


# ============================================================================
# Tests: Pattern Matcher - Operation Inference
# ============================================================================


class TestInferOperation:
    """Tests for operation inference from tool names."""

    @pytest.mark.parametrize(
        ("tool_name", "expected"),
        [
            ("read_file", "read"),
            ("get_user", "read"),
            ("list_files", "read"),
            ("fetch_data", "read"),
            ("search_logs", "read"),
        ],
        ids=["read", "get", "list", "fetch", "search"],
    )
    def test_infers_read_operation(self, tool_name, expected):
        """Given read-like tool name, infers 'read' operation."""
        # Act & Assert
        assert infer_operation(tool_name) == expected

    @pytest.mark.parametrize(
        ("tool_name", "expected"),
        [
            ("write_file", "write"),
            ("create_user", "write"),
            ("edit_config", "write"),
            ("update_record", "write"),
            ("save_document", "write"),
        ],
        ids=["write", "create", "edit", "update", "save"],
    )
    def test_infers_write_operation(self, tool_name, expected):
        """Given write-like tool name, infers 'write' operation."""
        # Act & Assert
        assert infer_operation(tool_name) == expected

    @pytest.mark.parametrize(
        ("tool_name", "expected"),
        [
            ("delete_file", "delete"),
            ("remove_user", "delete"),
            ("drop_table", "delete"),
            ("clear_cache", "delete"),
        ],
        ids=["delete", "remove", "drop", "clear"],
    )
    def test_infers_delete_operation(self, tool_name, expected):
        """Given delete-like tool name, infers 'delete' operation."""
        # Act & Assert
        assert infer_operation(tool_name) == expected

    @pytest.mark.parametrize(
        "tool_name",
        ["bash", "execute_command", "process_data"],
        ids=["bash", "execute", "process"],
    )
    def test_returns_none_for_unknown(self, tool_name):
        """Given ambiguous tool name, returns None (unknown operation)."""
        # Act & Assert
        assert infer_operation(tool_name) is None


# ============================================================================
# Tests: Pattern Matcher - Operation Matching
# ============================================================================


class TestMatchOperations:
    """Tests for operation constraint matching."""

    def test_none_constraint_matches_any_operation(self):
        """Given no constraint, matches any operation."""
        # Act & Assert
        assert _match_operations(None, "read") is True
        assert _match_operations(None, "write") is True
        assert _match_operations(None, None) is True

    @pytest.mark.parametrize(
        ("constraint", "operation", "expected"),
        [
            (["read"], "read", True),
            (["read"], "write", False),
            (["read", "write"], "write", True),
            (["read", "write", "delete"], "delete", True),
        ],
        ids=["single-match", "single-no-match", "multi-match", "all-operations"],
    )
    def test_constraint_matching(self, constraint, operation, expected):
        """Given operation constraint, returns expected match result."""
        # Act & Assert
        assert _match_operations(constraint, operation) == expected

    def test_unknown_operation_fails_specific_constraint(self):
        """Given specific constraint and unknown operation, returns False."""
        # Act & Assert
        assert _match_operations(["read"], None) is False


# ============================================================================
# Tests: Policy Engine - Discovery Methods
# ============================================================================


class TestPolicyEngineDiscovery:
    """Tests for discovery method handling."""

    def test_discovery_methods_bypass_policy(self, sample_policy, make_context):
        """Given discovery method, returns ALLOW without checking rules."""
        # Arrange
        engine = PolicyEngine(sample_policy)
        ctx = make_context(method="tools/list", category=ActionCategory.DISCOVERY)

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.ALLOW


# ============================================================================
# Tests: Policy Engine - Default Action
# ============================================================================


class TestPolicyEngineDefaultAction:
    """Tests for default action when no rules match."""

    def test_denies_when_no_match(self, make_context):
        """Given no matching rules, returns default DENY."""
        # Arrange
        policy = PolicyConfig(
            default_action="deny",
            rules=[
                PolicyRule(effect="allow", conditions=RuleConditions(tool_name="allowed_tool")),
            ],
        )
        engine = PolicyEngine(policy)
        ctx = make_context(tool_name="other_tool")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.DENY


# ============================================================================
# Tests: Policy Engine - Tool Name Matching
# ============================================================================


class TestPolicyEngineToolMatching:
    """Tests for tool name-based policy evaluation."""

    def test_denies_matching_tool(self, deny_bash_policy, make_context):
        """Given tool matching deny rule, returns DENY."""
        # Arrange
        engine = PolicyEngine(deny_bash_policy)
        ctx = make_context(tool_name="bash")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.DENY

    def test_allows_non_matching_tool(self, deny_bash_policy, make_context):
        """Given tool not matching deny rule, returns ALLOW."""
        # Arrange
        engine = PolicyEngine(deny_bash_policy)
        ctx = make_context(tool_name="safe_tool")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.ALLOW


# ============================================================================
# Tests: Policy Engine - Path Pattern Matching
# ============================================================================


class TestPolicyEnginePathMatching:
    """Tests for path pattern-based policy evaluation."""

    def test_denies_matching_path(self, path_based_policy, make_context):
        """Given path matching deny rule, returns DENY."""
        # Arrange
        engine = PolicyEngine(path_based_policy)
        ctx = make_context(path="/app/secrets/key.txt")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.DENY

    def test_allows_matching_path(self, path_based_policy, make_context):
        """Given path matching allow rule, returns ALLOW."""
        # Arrange
        engine = PolicyEngine(path_based_policy)
        ctx = make_context(path="/project/src/main.py")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.ALLOW

    def test_denies_unmatched_path(self, path_based_policy, make_context):
        """Given path matching no rule, returns default DENY."""
        # Arrange
        engine = PolicyEngine(path_based_policy)
        ctx = make_context(path="/other/file.txt")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.DENY


# ============================================================================
# Tests: Policy Engine - Combined Conditions (AND logic)
# ============================================================================


class TestPolicyEngineCombinedConditions:
    """Tests for AND logic in rule conditions."""

    @pytest.fixture
    def combined_conditions_policy(self):
        """Policy with combined tool + path conditions."""
        return PolicyConfig(
            rules=[
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(
                        tool_name="read_file",
                        path_pattern="/project/**",
                    ),
                ),
            ]
        )

    def test_allows_when_both_match(self, combined_conditions_policy, make_context):
        """Given both conditions match, returns ALLOW."""
        # Arrange
        engine = PolicyEngine(combined_conditions_policy)
        ctx = make_context(tool_name="read_file", path="/project/file.txt")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.ALLOW

    def test_denies_when_tool_matches_but_path_fails(self, combined_conditions_policy, make_context):
        """Given tool matches but path doesn't, returns DENY."""
        # Arrange
        engine = PolicyEngine(combined_conditions_policy)
        ctx = make_context(tool_name="read_file", path="/other/file.txt")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.DENY

    def test_denies_when_path_matches_but_tool_fails(self, combined_conditions_policy, make_context):
        """Given path matches but tool doesn't, returns DENY."""
        # Arrange
        engine = PolicyEngine(combined_conditions_policy)
        ctx = make_context(tool_name="write_file", path="/project/file.txt")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.DENY


# ============================================================================
# Tests: Policy Engine - Operation Inference
# ============================================================================


class TestPolicyEngineOperationInference:
    """Tests for operation-based policy evaluation."""

    @pytest.fixture
    def operation_policy(self):
        """Policy with operation-based rules."""
        return PolicyConfig(
            rules=[
                PolicyRule(effect="allow", conditions=RuleConditions(operations=["read"])),
                PolicyRule(effect="hitl", conditions=RuleConditions(operations=["write"])),
            ]
        )

    def test_allows_read_operation(self, operation_policy, make_context):
        """Given read-like tool, returns ALLOW."""
        # Arrange
        engine = PolicyEngine(operation_policy)
        ctx = make_context(tool_name="read_file")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.ALLOW

    def test_hitl_for_write_operation(self, operation_policy, make_context):
        """Given write-like tool, returns HITL."""
        # Arrange
        engine = PolicyEngine(operation_policy)
        ctx = make_context(tool_name="write_file")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.HITL

    def test_denies_unknown_operation(self, operation_policy, make_context):
        """Given tool with unknown operation, returns DENY."""
        # Arrange
        engine = PolicyEngine(operation_policy)
        ctx = make_context(tool_name="unknown_tool")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.DENY


# ============================================================================
# Tests: Policy Engine - Wildcard Matching
# ============================================================================


class TestPolicyEngineWildcard:
    """Tests for wildcard condition matching."""

    def test_wildcard_matches_all_tools(self, make_context):
        """Given wildcard tool_name, matches any tool."""
        # Arrange
        policy = PolicyConfig(
            rules=[
                PolicyRule(effect="allow", conditions=RuleConditions(tool_name="*")),
            ]
        )
        engine = PolicyEngine(policy)

        # Act & Assert
        assert engine.evaluate(make_context(tool_name="anything")) == Decision.ALLOW
        assert engine.evaluate(make_context(tool_name="other_thing")) == Decision.ALLOW


# ============================================================================
# Tests: Policy Engine - Combining Algorithm (HITL > DENY > ALLOW)
# ============================================================================


class TestPolicyEngineCombiningAlgorithm:
    """Tests for decision combining algorithm: HITL > DENY > ALLOW."""

    def test_deny_overrides_allow(self, make_context):
        """Given matching ALLOW and DENY rules, DENY wins."""
        # Arrange
        policy = PolicyConfig(
            rules=[
                PolicyRule(effect="allow", conditions=RuleConditions(tool_name="bash")),
                PolicyRule(effect="deny", conditions=RuleConditions(tool_name="bash")),
            ]
        )
        engine = PolicyEngine(policy)
        ctx = make_context(tool_name="bash")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.DENY

    def test_hitl_overrides_deny(self, make_context):
        """Given matching DENY and HITL rules, HITL wins."""
        # Arrange
        policy = PolicyConfig(
            rules=[
                PolicyRule(effect="deny", conditions=RuleConditions(tool_name="bash")),
                PolicyRule(effect="hitl", conditions=RuleConditions(tool_name="bash")),
            ]
        )
        engine = PolicyEngine(policy)
        ctx = make_context(tool_name="bash")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.HITL

    def test_hitl_overrides_allow(self, make_context):
        """Given matching ALLOW and HITL rules, HITL wins."""
        # Arrange
        policy = PolicyConfig(
            rules=[
                PolicyRule(effect="allow", conditions=RuleConditions(tool_name="bash")),
                PolicyRule(effect="hitl", conditions=RuleConditions(tool_name="bash")),
            ]
        )
        engine = PolicyEngine(policy)
        ctx = make_context(tool_name="bash")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.HITL


# ============================================================================
# Tests: Policy Engine - HITL Decision
# ============================================================================


class TestPolicyEngineHITL:
    """Tests for HITL decision handling."""

    def test_hitl_rule_returns_hitl_decision(self, sample_policy, make_context):
        """Given matching HITL rule, returns HITL decision."""
        # Arrange
        engine = PolicyEngine(sample_policy)
        ctx = make_context(tool_name="write_file", path="/project/config.json")

        # Act
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.HITL


# ============================================================================
# Tests: Integration - Full Policy Workflow
# ============================================================================


class TestPolicyIntegration:
    """Integration tests for the full policy workflow."""

    def test_create_save_load_evaluate(self, temp_policy_dir, make_context):
        """Given complete workflow, policy correctly evaluates after save/load."""
        # Arrange - Create policy
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="deny-dangerous",
                    effect="deny",
                    conditions=RuleConditions(tool_name="bash"),
                ),
                PolicyRule(
                    id="allow-reads",
                    effect="allow",
                    conditions=RuleConditions(operations=["read"]),
                ),
            ]
        )

        # Act - Save and load
        path = temp_policy_dir / "policy.json"
        save_policy(policy, path)
        loaded = load_policy(path)

        # Act - Evaluate
        engine = PolicyEngine(loaded)
        ctx = make_context(tool_name="bash")
        decision = engine.evaluate(ctx)

        # Assert
        assert decision == Decision.DENY


# ============================================================================
# Tests: Policy Engine - Critical Failures
# ============================================================================


class TestPolicyEngineCriticalFailures:
    """Tests for PolicyEnforcementFailure on unexpected errors."""

    def test_raises_policy_enforcement_failure_on_unexpected_error(self, make_context, monkeypatch):
        """Given unexpected exception during evaluation, raises PolicyEnforcementFailure."""
        # Arrange
        policy = PolicyConfig(rules=[PolicyRule(effect="allow", conditions=RuleConditions(tool_name="*"))])
        engine = PolicyEngine(policy)
        ctx = make_context(tool_name="test")

        # Simulate unexpected error in _rule_matches
        def raise_error(*args, **kwargs):
            raise RuntimeError("Unexpected internal error")

        monkeypatch.setattr(engine, "_rule_matches", raise_error)

        # Act & Assert
        with pytest.raises(PolicyEnforcementFailure, match="Policy evaluation failed unexpectedly"):
            engine.evaluate(ctx)

    def test_policy_enforcement_failure_includes_original_error(self, make_context, monkeypatch):
        """Given unexpected exception, PolicyEnforcementFailure includes original error details."""
        # Arrange
        policy = PolicyConfig(rules=[PolicyRule(effect="allow", conditions=RuleConditions(tool_name="*"))])
        engine = PolicyEngine(policy)
        ctx = make_context(tool_name="test")

        def raise_error(*args, **kwargs):
            raise ValueError("Bad value in rule matching")

        monkeypatch.setattr(engine, "_rule_matches", raise_error)

        # Act & Assert
        with pytest.raises(PolicyEnforcementFailure) as exc_info:
            engine.evaluate(ctx)

        assert "ValueError" in str(exc_info.value)
        assert "Bad value in rule matching" in str(exc_info.value)
        assert exc_info.value.__cause__ is not None


# ============================================================================
# Tests: List/OR Logic for Conditions
# ============================================================================


class TestMatchAny:
    """Tests for _match_any helper function."""

    def test_none_pattern_matches_anything(self):
        """Given None pattern, matches any value."""
        assert _match_any(None, "anything", match_tool_name) is True
        assert _match_any(None, None, match_tool_name) is True

    def test_single_string_pattern_uses_match_fn(self):
        """Given single string pattern, uses match function directly."""
        assert _match_any("bash", "bash", match_tool_name) is True
        assert _match_any("bash", "rm", match_tool_name) is False
        assert _match_any("write_*", "write_file", match_tool_name) is True

    def test_empty_list_never_matches(self):
        """Given empty list, never matches (no valid values)."""
        assert _match_any([], "bash", match_tool_name) is False
        assert _match_any([], None, match_tool_name) is False

    def test_list_matches_if_any_pattern_matches(self):
        """Given list of patterns, matches if ANY matches (OR logic)."""
        patterns = ["bash", "rm", "mv"]
        assert _match_any(patterns, "bash", match_tool_name) is True
        assert _match_any(patterns, "rm", match_tool_name) is True
        assert _match_any(patterns, "mv", match_tool_name) is True
        assert _match_any(patterns, "cp", match_tool_name) is False

    def test_list_with_glob_patterns(self):
        """Given list with glob patterns, matches if any pattern matches."""
        patterns = ["write_*", "edit_*", "save_*"]
        assert _match_any(patterns, "write_file", match_tool_name) is True
        assert _match_any(patterns, "edit_document", match_tool_name) is True
        assert _match_any(patterns, "read_file", match_tool_name) is False

    def test_works_with_path_pattern_matcher(self):
        """Given path patterns, works with match_path_pattern."""
        patterns = ["/project/**", "/tmp/**"]
        assert _match_any(patterns, "/project/src/main.py", match_path_pattern) is True
        assert _match_any(patterns, "/tmp/cache.txt", match_path_pattern) is True
        assert _match_any(patterns, "/etc/passwd", match_path_pattern) is False


class TestListConditionsModel:
    """Tests for RuleConditions accepting list values."""

    def test_tool_name_accepts_single_string(self):
        """Given single string tool_name, creates conditions successfully."""
        conditions = RuleConditions(tool_name="bash")
        assert conditions.tool_name == "bash"

    def test_tool_name_accepts_list(self):
        """Given list of tool names, creates conditions successfully."""
        conditions = RuleConditions(tool_name=["bash", "rm", "mv"])
        assert conditions.tool_name == ["bash", "rm", "mv"]

    def test_path_pattern_accepts_list(self):
        """Given list of path patterns, creates conditions successfully."""
        conditions = RuleConditions(path_pattern=["/project/**", "/tmp/**"])
        assert conditions.path_pattern == ["/project/**", "/tmp/**"]

    def test_multiple_list_conditions(self):
        """Given multiple list conditions, creates conditions successfully."""
        conditions = RuleConditions(
            tool_name=["bash", "rm"],
            path_pattern=["/etc/**", "/var/**"],
        )
        assert conditions.tool_name == ["bash", "rm"]
        assert conditions.path_pattern == ["/etc/**", "/var/**"]

    def test_rejects_empty_string(self):
        """Given empty string, raises ValidationError."""
        with pytest.raises(ValidationError, match="empty or whitespace"):
            RuleConditions(tool_name="")

    def test_rejects_whitespace_only_string(self):
        """Given whitespace-only string, raises ValidationError."""
        with pytest.raises(ValidationError, match="empty or whitespace"):
            RuleConditions(tool_name="   ")

    def test_rejects_empty_string_in_list(self):
        """Given list containing empty string, raises ValidationError."""
        with pytest.raises(ValidationError, match="empty or whitespace"):
            RuleConditions(tool_name=["bash", ""])

    def test_rejects_whitespace_in_list(self):
        """Given list containing whitespace-only string, raises ValidationError."""
        with pytest.raises(ValidationError, match="empty or whitespace"):
            RuleConditions(tool_name=["bash", "   "])


class TestListConditionsEngine:
    """Tests for PolicyEngine with list conditions."""

    def test_tool_name_list_matches_any(self, make_context):
        """Given tool_name list, matches if tool is ANY in list."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="deny",
                    conditions=RuleConditions(tool_name=["bash", "rm", "mv"]),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Should deny bash, rm, mv
        assert engine.evaluate(make_context(tool_name="bash")) == Decision.DENY
        assert engine.evaluate(make_context(tool_name="rm")) == Decision.DENY
        assert engine.evaluate(make_context(tool_name="mv")) == Decision.DENY

        # Should use default (deny) for other tools - no allow rule
        assert engine.evaluate(make_context(tool_name="cp")) == Decision.DENY

    def test_tool_name_list_with_allow_rule(self, make_context):
        """Given tool_name list in allow rule, allows matching tools."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(tool_name=["read_file", "list_dir"]),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Should allow read_file and list_dir
        assert engine.evaluate(make_context(tool_name="read_file")) == Decision.ALLOW
        assert engine.evaluate(make_context(tool_name="list_dir")) == Decision.ALLOW

        # Should deny other tools (default action)
        assert engine.evaluate(make_context(tool_name="write_file")) == Decision.DENY

    def test_path_pattern_list_matches_any(self, make_context):
        """Given path_pattern list, matches if path matches ANY pattern."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(
                        tool_name="read_file",
                        path_pattern=["/project/**", "/tmp/**"],
                    ),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Should allow paths matching either pattern
        assert (
            engine.evaluate(make_context(tool_name="read_file", path="/project/src/main.py"))
            == Decision.ALLOW
        )
        assert engine.evaluate(make_context(tool_name="read_file", path="/tmp/cache.txt")) == Decision.ALLOW

        # Should deny path not matching any pattern
        assert engine.evaluate(make_context(tool_name="read_file", path="/etc/passwd")) == Decision.DENY

    def test_mixed_list_and_single_uses_and_logic(self, make_context):
        """Given list in one field and single in another, uses AND across fields."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="deny",
                    conditions=RuleConditions(
                        tool_name=["bash", "rm"],  # OR within
                        path_pattern="/etc/**",  # AND with this
                    ),
                ),
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(tool_name="*"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Should deny: (bash OR rm) AND /etc/**
        assert engine.evaluate(make_context(tool_name="bash", path="/etc/passwd")) == Decision.DENY
        assert engine.evaluate(make_context(tool_name="rm", path="/etc/passwd")) == Decision.DENY

        # Should allow: bash on non-/etc path (doesn't match deny rule)
        assert engine.evaluate(make_context(tool_name="bash", path="/project/file")) == Decision.ALLOW

        # Should allow: cp on /etc (doesn't match deny rule - tool not in list)
        assert engine.evaluate(make_context(tool_name="cp", path="/etc/passwd")) == Decision.ALLOW

    def test_empty_list_never_matches(self, make_context):
        """Given empty list, rule never matches."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="deny",
                    conditions=RuleConditions(tool_name=[]),  # Empty list
                ),
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(tool_name="*"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Empty list rule never matches, so allow rule applies
        assert engine.evaluate(make_context(tool_name="bash")) == Decision.ALLOW
        assert engine.evaluate(make_context(tool_name="anything")) == Decision.ALLOW

    def test_glob_patterns_in_list(self, make_context):
        """Given list with glob patterns, each pattern is matched."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="deny",
                    conditions=RuleConditions(tool_name=["write_*", "edit_*", "delete_*"]),
                ),
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(tool_name="*"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Should deny write_*, edit_*, delete_*
        assert engine.evaluate(make_context(tool_name="write_file")) == Decision.DENY
        assert engine.evaluate(make_context(tool_name="edit_document")) == Decision.DENY
        assert engine.evaluate(make_context(tool_name="delete_record")) == Decision.DENY

        # Should allow read_* (doesn't match any deny pattern)
        assert engine.evaluate(make_context(tool_name="read_file")) == Decision.ALLOW

    def test_backward_compat_single_string_still_works(self, make_context):
        """Given single string values (old format), still works."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="deny",
                    conditions=RuleConditions(tool_name="bash"),
                ),
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(tool_name="*"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        assert engine.evaluate(make_context(tool_name="bash")) == Decision.DENY
        assert engine.evaluate(make_context(tool_name="safe_tool")) == Decision.ALLOW


# ============================================================================
# Tests: Subject-Based Conditions
# ============================================================================


class TestSubjectBasedConditions:
    """Tests for subject_id policy conditions.

    These tests verify that policies can filter by user identity,
    which is security-critical for multi-user deployments.
    """

    def test_subject_id_exact_match_allows(self, make_context):
        """Given subject_id condition, allows matching user."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(subject_id="alice"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Alice should be allowed
        assert engine.evaluate(make_context(subject_id="alice")) == Decision.ALLOW

        # Bob should be denied (default action)
        assert engine.evaluate(make_context(subject_id="bob")) == Decision.DENY

    def test_subject_id_exact_match_denies(self, make_context):
        """Given subject_id deny rule, denies matching user."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="deny",
                    conditions=RuleConditions(subject_id="mallory"),
                ),
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(tool_name="*"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Mallory should be denied
        assert engine.evaluate(make_context(subject_id="mallory")) == Decision.DENY

        # Alice should be allowed (falls through to allow rule)
        assert engine.evaluate(make_context(subject_id="alice")) == Decision.ALLOW

    def test_subject_id_is_case_sensitive(self, make_context):
        """Given subject_id condition, matching is case-sensitive."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(subject_id="Alice"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Exact case matches
        assert engine.evaluate(make_context(subject_id="Alice")) == Decision.ALLOW

        # Different case does NOT match (case-sensitive)
        assert engine.evaluate(make_context(subject_id="alice")) == Decision.DENY
        assert engine.evaluate(make_context(subject_id="ALICE")) == Decision.DENY

    def test_subject_id_list_matches_any(self, make_context):
        """Given subject_id list, allows any user in list."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(subject_id=["alice", "bob", "charlie"]),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # All listed users should be allowed
        assert engine.evaluate(make_context(subject_id="alice")) == Decision.ALLOW
        assert engine.evaluate(make_context(subject_id="bob")) == Decision.ALLOW
        assert engine.evaluate(make_context(subject_id="charlie")) == Decision.ALLOW

        # Unlisted user should be denied
        assert engine.evaluate(make_context(subject_id="mallory")) == Decision.DENY

    def test_subject_id_combined_with_tool_name(self, make_context):
        """Given subject_id AND tool_name, both must match."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="admin-bash",
                    effect="allow",
                    conditions=RuleConditions(
                        subject_id="admin",
                        tool_name="bash",
                    ),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Admin using bash - allowed
        assert engine.evaluate(make_context(subject_id="admin", tool_name="bash")) == Decision.ALLOW

        # Admin using other tool - denied (tool doesn't match)
        assert engine.evaluate(make_context(subject_id="admin", tool_name="rm")) == Decision.DENY

        # Non-admin using bash - denied (subject doesn't match)
        assert engine.evaluate(make_context(subject_id="user", tool_name="bash")) == Decision.DENY

    def test_subject_id_combined_with_path(self, make_context):
        """Given subject_id AND path_pattern, both must match."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="alice-home",
                    effect="allow",
                    conditions=RuleConditions(
                        subject_id="alice",
                        path_pattern="/home/alice/**",
                    ),
                ),
                PolicyRule(
                    id="bob-home",
                    effect="allow",
                    conditions=RuleConditions(
                        subject_id="bob",
                        path_pattern="/home/bob/**",
                    ),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Alice accessing her home - allowed
        assert (
            engine.evaluate(make_context(subject_id="alice", path="/home/alice/file.txt")) == Decision.ALLOW
        )

        # Alice accessing Bob's home - denied
        assert engine.evaluate(make_context(subject_id="alice", path="/home/bob/file.txt")) == Decision.DENY

        # Bob accessing his home - allowed
        assert engine.evaluate(make_context(subject_id="bob", path="/home/bob/file.txt")) == Decision.ALLOW

    def test_subject_id_hitl_for_elevated_actions(self, make_context):
        """Given HITL rule with subject_id, requires approval for user."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="intern-needs-approval",
                    effect="hitl",
                    conditions=RuleConditions(
                        subject_id="intern",
                        tool_name="write_*",
                    ),
                ),
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(tool_name="*"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Intern writing needs HITL approval
        assert engine.evaluate(make_context(subject_id="intern", tool_name="write_file")) == Decision.HITL

        # Intern reading is allowed (doesn't match write_*)
        assert engine.evaluate(make_context(subject_id="intern", tool_name="read_file")) == Decision.ALLOW

        # Senior dev writing is allowed (subject doesn't match)
        assert engine.evaluate(make_context(subject_id="senior", tool_name="write_file")) == Decision.ALLOW

    def test_subject_id_oidc_format(self, make_context):
        """Given OIDC-style subject_id (issuer|id), matches correctly."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    effect="allow",
                    conditions=RuleConditions(
                        subject_id=["auth0|user123", "google-oauth2|user456"],
                    ),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # OIDC-style IDs should match exactly
        assert engine.evaluate(make_context(subject_id="auth0|user123")) == Decision.ALLOW
        assert engine.evaluate(make_context(subject_id="google-oauth2|user456")) == Decision.ALLOW

        # Partial match should NOT work
        assert engine.evaluate(make_context(subject_id="user123")) == Decision.DENY
        assert engine.evaluate(make_context(subject_id="auth0|user456")) == Decision.DENY
