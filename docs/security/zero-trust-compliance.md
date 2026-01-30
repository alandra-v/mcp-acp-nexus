# Zero Trust Architecture Compliance

Analysis of mcp-acp against NIST SP 800-207 Zero Trust Architecture.

## NIST ZTA Tenets

For reference, the seven tenets from NIST SP 800-207:

| # | Tenet |
|---|-------|
| 1 | All data sources and computing services are considered resources |
| 2 | All communication is secured regardless of network location |
| 3 | Access to individual enterprise resources is granted on a per-session basis |
| 4 | Access to resources is determined by dynamic policy |
| 5 | The enterprise monitors and measures the integrity and security posture of all owned and associated assets |
| 6 | All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| 7 | The enterprise collects as much information as possible about the current state of assets and uses it to improve security posture |

## Feature → Tenet Mapping

| Feature | Description | Tenets |
|---------|-------------|--------|
| OIDC Authentication | JWT validation with configured identity provider | 6 |
| Device Health Checks | FileVault and SIP verification at startup and runtime (macOS) | 5 |
| ABAC Policy Engine | Attribute-based access control with configurable rules | 4 |
| Tool-Level Policies | Per-tool access rules with side effect classification | 1, 4 |
| HITL Approval | Human-in-the-loop for sensitive operations | 4, 6 |
| Session Management | User-bound sessions with time limits and secure IDs | 3, 6 |
| Device Health Monitor | Periodic re-checks during session (5-minute intervals) | 5 |
| Fail-Closed Audit | Operations blocked if audit logging fails; fallback chain | 7 |
| mTLS Backend | Optional mutual TLS for backend connections | 2 |
| Machine-Bound Token Storage | Tokens encrypted with machine-specific key | 3 |

## Tenet Coverage Analysis

| Tenet | Coverage | Implementation |
|-------|----------|----------------|
| 1 - Resources | Partial | Tools treated as resources with per-tool policies |
| 2 - Secure Communication | Full | mTLS available; STDIO inherently local |
| 3 - Per-Session Access | Full | User-bound sessions; machine-bound token storage |
| 4 - Dynamic Policy | Full | ABAC engine with context-aware rules |
| 5 - Asset Integrity | Partial | Device health checks at startup and runtime; no asset inventory |
| 6 - Dynamic AuthZ | Full | Per-request policy evaluation with HITL |
| 7 - Security Telemetry | Partial | Fail-closed audit with fallback chain; no behavioral analysis |

## Architectural Limitations

These limitations stem from the proxy's architecture and use case, not implementation gaps.

### Desktop Single-User Architecture

The proxy runs as a desktop application for a single user, not as an enterprise service. This affects:

- **Control/data plane separation**: Logical separation exists in code, but physical separation (separate services) adds deployment complexity inappropriate for desktop use.
- **IdP resilience**: Users configure one identity provider. Fallback IdP assumes multiple providers, which is uncommon for individual users.

### Per-Session Lifecycle

The proxy runs per-MCP-session (started by Claude Desktop, ends when session ends). This affects:

- **Dynamic policy updates**: Hot-reloading adds complexity for limited benefit. Restarting the proxy applies new policy, which is acceptable for short sessions.
- **Continuous re-authentication**: Token refresh already re-validates with IdP. Additional re-auth during typical session durations provides marginal benefit.

### Proxy Scope Boundary

The proxy controls the client→backend path. Some ZTA concerns are outside this scope:

- **Network segmentation**: VLANs, firewalls, service mesh are infrastructure concerns.
- **Backend trust**: User configures which backend to use, establishing trust at configuration time. The proxy protects the backend from unauthorized clients, not vice versa.

## Deferred Work

Features deferred from Stage 3 PoC. See [roadmap.md](../design/roadmap.md) for details.

| Roadmap Item | Tenet | Why Deferred |
|--------------|-------|--------------|
| Tool Registry | 1, 5 | Hardcoded mapping demonstrates concept |
| Tool Arguments in Policy | 4 | Path extraction covers most cases |
| Approval-Aware Conditions | 4 | Current caching is sufficient |
| Content Inspection | 7 | Core enforcement works without it |
| Behavioral Analysis | 5, 7 | Requires research and statistical infrastructure |

## Out of Scope

Beyond web development or proxy architecture:

| Item | Reason |
|------|--------|
| Network micro-segmentation | Infrastructure (VLANs, firewalls, service mesh) |
| ML behavioral analytics | Requires ML pipelines, baselines, statistical analysis |
| Full disk encryption | OS-level (FileVault already required for device health) |

## References

- NIST SP 800-207: Zero Trust Architecture
- [roadmap.md](../design/roadmap.md) - Deferred improvements
