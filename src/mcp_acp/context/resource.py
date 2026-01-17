"""Resource models - ON WHAT is the operation being performed.

Named "Resource" instead of "Object" to avoid conflict with Python's
built-in object type. In ABAC terminology, this is the "Object" -
what is being accessed.

Structure:
- Resource: Top-level container
  - server: ServerInfo (always populated from config)
  - tool: ToolInfo (for tools/call)
  - resource: ResourceInfo (for file/URI access)
"""

from __future__ import annotations

__all__ = [
    "Resource",
    "ResourceInfo",
    "ResourceType",
    "ServerInfo",
    "SideEffect",
    "ToolInfo",
]

from enum import Enum

from pydantic import BaseModel, ConfigDict

from mcp_acp.context.provenance import Provenance


class ResourceType(str, Enum):
    """Type of resource being accessed."""

    TOOL = "tool"
    RESOURCE = "resource"  # MCP resource (file, URI)
    PROMPT = "prompt"
    SERVER = "server"


class SideEffect(str, Enum):
    """Known tool side effects for policy decisions.

    Used to categorize what a tool might do, enabling policies like:
    - "Deny all tools with NETWORK_EGRESS"
    - "Require approval for CODE_EXEC"
    - "Allow FS_READ but not FS_WRITE for this user"

    Categories:
    - Filesystem: FS_READ, FS_WRITE
    - Database: DB_READ, DB_WRITE
    - Network: NETWORK_EGRESS, NETWORK_INGRESS
    - Execution: CODE_EXEC, PROCESS_SPAWN, SUDO_ELEVATE
    - Secrets: SECRETS_READ, ENV_READ, KEYCHAIN_READ
    - System: CLIPBOARD_READ, CLIPBOARD_WRITE, BROWSER_OPEN
    - Sensitive: SCREEN_CAPTURE, AUDIO_CAPTURE, CAMERA_CAPTURE
    - Cloud: CLOUD_API, CONTAINER_EXEC
    - Communication: EMAIL_SEND
    """

    # Filesystem
    FS_READ = "fs_read"
    FS_WRITE = "fs_write"

    # Database
    DB_READ = "db_read"
    DB_WRITE = "db_write"

    # Network
    NETWORK_EGRESS = "network_egress"
    NETWORK_INGRESS = "network_ingress"

    # Code execution
    CODE_EXEC = "code_exec"
    PROCESS_SPAWN = "process_spawn"
    SUDO_ELEVATE = "sudo_elevate"

    # Secrets and credentials
    SECRETS_READ = "secrets_read"
    ENV_READ = "env_read"
    KEYCHAIN_READ = "keychain_read"

    # System resources
    CLIPBOARD_READ = "clipboard_read"
    CLIPBOARD_WRITE = "clipboard_write"
    BROWSER_OPEN = "browser_open"

    # Sensitive capture
    SCREEN_CAPTURE = "screen_capture"
    AUDIO_CAPTURE = "audio_capture"
    CAMERA_CAPTURE = "camera_capture"

    # Cloud and containers
    CLOUD_API = "cloud_api"
    CONTAINER_EXEC = "container_exec"

    # Communication
    EMAIL_SEND = "email_send"


class ServerInfo(BaseModel):
    """Backend MCP server identity.

    Populated from config.backend.server_name.
    """

    id: str
    provenance: Provenance

    model_config = ConfigDict(frozen=True)


class ToolInfo(BaseModel):
    """Tool being invoked (for tools/call requests).

    Attributes:
        name: Tool name from request
        provenance: Where we got the tool name (MCP_REQUEST)
        version: Tool version if known from registry
        risk_tier: Risk classification ("low", "medium", "high", "critical")
        side_effects: Known side effects from registry or manual map
        side_effects_provenance: Where side effects came from
    """

    name: str
    provenance: Provenance

    # Registry fields (empty until registry exists)
    version: str | None = None
    risk_tier: str | None = None

    # Side effects - start with manual map, later from registry
    side_effects: frozenset[SideEffect] | None = None
    side_effects_provenance: Provenance | None = None

    model_config = ConfigDict(frozen=True)


class ResourceInfo(BaseModel):
    """MCP resource being accessed (file, URI).

    Used for resources/read and tools that access files.

    Attributes:
        uri: Full URI if provided
        scheme: URI scheme (file, http, db, etc.)
        path: Normalized file path if applicable (first/primary path found)
        source_path: Source path for move/copy operations
        dest_path: Destination path for move/copy operations
        filename: Base filename
        extension: File extension
        parent_dir: Parent directory path
        provenance: Where we got this info (MCP_REQUEST)
        classification: Future - classification from URI prefix rules
    """

    uri: str | None = None
    scheme: str | None = None
    path: str | None = None
    source_path: str | None = None
    dest_path: str | None = None
    filename: str | None = None
    extension: str | None = None
    parent_dir: str | None = None
    provenance: Provenance

    # Future: classification from URI prefix rules
    classification: str | None = None

    model_config = ConfigDict(frozen=True)


class Resource(BaseModel):
    """The target of the operation (ABAC Object).

    Named 'Resource' to avoid Python's built-in 'object'.
    In ABAC this is the Object - what is being accessed.

    Attributes:
        type: What kind of resource (tool, resource, prompt, server)
        server: Backend server identity (always populated from config)
        tool: Tool info (for tools/call)
        resource: File/URI info (for resources/read or tools with paths)
    """

    type: ResourceType
    server: ServerInfo

    # One of these populated based on type
    tool: ToolInfo | None = None
    resource: ResourceInfo | None = None

    model_config = ConfigDict(frozen=True)
