# Security Policy

## Reporting a Vulnerability

The AumOS platform team takes security vulnerabilities seriously. We appreciate your
efforts to responsibly disclose your findings.

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

Email your findings to: **security@aumos.io**

Include in your report:
- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Any proof-of-concept code (if applicable)
- Your recommended fix (if you have one)

You will receive an acknowledgment within **48 hours** and a detailed response
within **5 business days**.

## Governance Engine — Additional Security Scope

Because `aumos-governance-engine` manages compliance and audit trails for enterprise
AI systems, the following additional areas are in scope:

- **Audit Wall bypass** — any mechanism that allows modifying `gov_audit_trail_entries`
  after initial insertion (UPDATE, DELETE, or TRUNCATE on the audit table)
- **Policy evaluation manipulation** — input injection into OPA Rego evaluation that
  causes incorrect allow/deny decisions
- **Regulation mapping spoofing** — manipulating control mappings to falsely indicate
  compliance with a regulation
- **Evidence tampering** — modifying evidence records after submission
- **Cross-tenant audit trail access** — reading another tenant's audit entries

## Scope

The following are in scope for security reports:

- Authentication and authorization bypass
- Tenant isolation violations (RLS bypass, cross-tenant data access)
- SQL injection or other injection attacks
- Remote code execution
- Sensitive data exposure (credentials, PII, tenant data)
- Privilege escalation
- API security issues (broken object-level authorization, rate limiting bypass)
- Audit trail immutability violations
- OPA policy injection or manipulation

The following are out of scope:

- Denial of service attacks
- Social engineering of AumOS staff
- Physical security issues
- Vulnerabilities in third-party services we do not control
- Issues in repositories not owned by AumOS Enterprise

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Status update | Every 7 days during investigation |
| Fix deployment (critical) | Within 7 days of confirmation |
| Fix deployment (high) | Within 30 days of confirmation |
| Fix deployment (medium/low) | Next scheduled release |

## Disclosure Policy

- We follow a **90-day coordinated disclosure** policy
- We will notify you when the fix is deployed
- We will credit you in our release notes (unless you prefer anonymity)
- We ask that you do not publicly disclose the vulnerability until we have released a fix

## Security Best Practices for Contributors

When contributing to this repository:

1. Never commit secrets, API keys, or credentials (even test credentials)
2. Use parameterized queries — never string concatenation in SQL
3. Validate all inputs at system boundaries using Pydantic
4. Never log sensitive data (tokens, passwords, PII, Rego policy content that may
   reveal internal control logic)
5. Check dependency licenses and security advisories before adding packages
6. Do not add any mechanism that could allow modifying or deleting audit trail entries
7. All OPA policy input must be validated with Pydantic before being forwarded to OPA
8. Report any security issues you discover, even if you are not sure of the impact
