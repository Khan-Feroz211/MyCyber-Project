# SOC 2 Control Mapping (Scaffold)

## Scope

This is a working control map for Trust Services Criteria (Security-focused baseline).

## Legend

- **Satisfied**: Implemented in code/infrastructure now
- **Policy Needed**: Requires formal policy/process evidence
- **Partial**: Technical baseline exists, operational evidence still needed

## Control Map

| SOC 2 Area | Current Mapping | Status | Notes |
|---|---|---|---|
| CC6 Logical access | JWT auth, MFA support, RBAC roles | Partial | Need account lifecycle policy + access review evidence |
| CC7 Change management | Git-based changes + CI test execution | Partial | Need formal change approval / release policy |
| CC7 Monitoring | Security events + immutable audit log chain | Satisfied | Add alerting retention and incident workflow policy |
| CC8 Vulnerability management | Security scanning hooks and hardening docs | Partial | Need recurring vulnerability scan policy + tracking |
| A1 Availability operations | Health endpoints and runtime monitoring | Partial | Need uptime/SLA runbook and incident response policy |
| PI1 Data processing integrity | Pre/post scan checks in LLM and DLP flow | Satisfied | Keep verification tests as evidence |
| C1 Confidentiality | Encryption-at-rest controls and key versioning | Partial | Need key rotation policy and data classification policy |

