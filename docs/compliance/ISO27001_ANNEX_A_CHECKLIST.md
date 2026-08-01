# ISO/IEC 27001 Annex A Checklist (Scaffold)

## Legend

- **Satisfied**: Technical control present
- **Policy Needed**: Governance/process documentation required
- **Partial**: Implemented but missing evidence/process maturity

## Annex A Control Snapshot

| Annex A Theme | Example Control | Status | Evidence / Gap |
|---|---|---|---|
| Organizational controls | Security roles and responsibilities | Partial | RBAC exists; formal RACI/policy needed |
| Organizational controls | Information security in project management | Policy Needed | Need documented SDLC security policy |
| People controls | Identity and access management responsibilities | Partial | MFA/RBAC implemented; joiner/mover/leaver policy needed |
| Physical controls | Secure areas / physical protection | Policy Needed | Outside app code; document hosting controls |
| Technological controls | Access restriction | Satisfied | JWT + role checks on protected routes |
| Technological controls | Cryptography | Partial | Encryption controls exist; key management policy needed |
| Technological controls | Logging and monitoring | Satisfied | Immutable hash-chained audit logs implemented |
| Technological controls | Secure development lifecycle | Partial | Tests and code review in place; formal secure SDLC policy needed |
| Technological controls | Backup and recovery | Policy Needed | Need tested backup/restore procedure evidence |
| Technological controls | Information deletion | Policy Needed | Need retention/deletion policy and proof of execution |

