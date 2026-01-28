"""API schemas (Pydantic models) for request/response validation.

Centralized schemas for all API routes.
"""

from __future__ import annotations

# Auth schemas
from mcp_acp.api.schemas.auth import (
    AuthStatusResponse,
    DeviceFlowPollResponse,
    DeviceFlowStartResponse,
    FederatedLogoutResponse,
    LogoutResponse,
    NotifyResponse,
)

# Config schemas
from mcp_acp.api.schemas.config import (
    ApiKeyResponse,
    ApiKeySetRequest,
    AuthConfigResponse,
    AuthConfigUpdate,
    BackendConfigResponse,
    BackendConfigUpdate,
    ConfigChange,
    ConfigComparisonResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    ConfigUpdateResponse,
    HITLConfigResponse,
    HITLConfigUpdate,
    HttpTransportResponse,
    HttpTransportUpdate,
    LoggingConfigResponse,
    LoggingConfigUpdate,
    MTLSConfigResponse,
    MTLSConfigUpdate,
    OIDCConfigResponse,
    OIDCConfigUpdate,
    ProxyConfigResponse,
    ProxyConfigUpdate,
    StdioAttestationResponse,
    StdioAttestationUpdate,
    StdioTransportResponse,
    StdioTransportUpdate,
)

# Policy schemas
from mcp_acp.api.schemas.policy import (
    PolicyFullUpdate,
    PolicyResponse,
    PolicyRuleCreate,
    PolicyRuleMutationResponse,
    PolicyRuleResponse,
    PolicySchemaResponse,
)

# Approvals schemas
from mcp_acp.api.schemas.approvals import (
    ApprovalCacheResponse,
    CachedApprovalResponse,
    ClearApprovalsResponse,
    DeleteApprovalResponse,
)

# Control schemas
from mcp_acp.api.schemas.control import (
    ProxyStatus,
    ReloadResponse,
)

# Pending schemas
from mcp_acp.api.schemas.pending import (
    ApprovalActionResponse,
    PendingApprovalResponse,
)

# Proxies schemas
from mcp_acp.api.schemas.proxies import (
    ProxyResponse,
    StatsResponse,
)

# Sessions schemas
from mcp_acp.api.schemas.sessions import (
    AuthSessionResponse,
)

# Logs schemas
from mcp_acp.api.schemas.logs import (
    LogFileInfo,
    LogFolderInfo,
    LogsMetadataResponse,
    LogsResponse,
)

# Incidents schemas
from mcp_acp.api.schemas.incidents import (
    IncidentsSummary,
)

# Audit schemas
from mcp_acp.api.schemas.audit import (
    AuditFileResult,
    AuditRepairResponse,
    AuditRepairResult,
    AuditVerifyResponse,
)

# Error schemas (for API documentation)
from mcp_acp.api.schemas.errors import (
    ErrorDetail,
    ErrorResponse,
    ValidationErrorItem,
)

__all__ = [
    # Auth
    "AuthStatusResponse",
    "DeviceFlowPollResponse",
    "DeviceFlowStartResponse",
    "FederatedLogoutResponse",
    "LogoutResponse",
    "NotifyResponse",
    # Config
    "ApiKeyResponse",
    "ApiKeySetRequest",
    "AuthConfigResponse",
    "AuthConfigUpdate",
    "BackendConfigResponse",
    "BackendConfigUpdate",
    "ConfigChange",
    "ConfigComparisonResponse",
    "ConfigResponse",
    "ConfigUpdateRequest",
    "ConfigUpdateResponse",
    "HITLConfigResponse",
    "HITLConfigUpdate",
    "HttpTransportResponse",
    "HttpTransportUpdate",
    "LoggingConfigResponse",
    "LoggingConfigUpdate",
    "MTLSConfigResponse",
    "MTLSConfigUpdate",
    "OIDCConfigResponse",
    "OIDCConfigUpdate",
    "ProxyConfigResponse",
    "ProxyConfigUpdate",
    "StdioAttestationResponse",
    "StdioAttestationUpdate",
    "StdioTransportResponse",
    "StdioTransportUpdate",
    # Policy
    "PolicyFullUpdate",
    "PolicyResponse",
    "PolicyRuleCreate",
    "PolicyRuleMutationResponse",
    "PolicyRuleResponse",
    "PolicySchemaResponse",
    # Approvals
    "ApprovalCacheResponse",
    "CachedApprovalResponse",
    "ClearApprovalsResponse",
    "DeleteApprovalResponse",
    # Control
    "ProxyStatus",
    "ReloadResponse",
    # Pending
    "ApprovalActionResponse",
    "PendingApprovalResponse",
    # Proxies
    "ProxyResponse",
    "StatsResponse",
    # Sessions
    "AuthSessionResponse",
    # Logs
    "LogFileInfo",
    "LogFolderInfo",
    "LogsMetadataResponse",
    "LogsResponse",
    # Incidents
    "IncidentsSummary",
    # Audit
    "AuditFileResult",
    "AuditRepairResponse",
    "AuditRepairResult",
    "AuditVerifyResponse",
    # Errors
    "ErrorDetail",
    "ErrorResponse",
    "ValidationErrorItem",
]
