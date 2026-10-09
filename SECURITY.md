# Security Policy

## Supported Versions

Only the current `main` branch of SVS-Cyber is actively supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability within SVS-Cyber, please submit an issue to the private tracker or reach out directly to the maintainers. Do not disclose vulnerabilities in public issues or discussions prior to coordination.

## Security Practices

- **Tool Execution:** Tools that invoke shell commands or interact with the operating system are restricted and must be audited using the `security-reviewer` agent.
- **Secrets Management:** Secrets and keys must not be hardcoded; they must be managed exclusively via `key_manager.py` or `.env` files.
- **Dependency Scanning:** We utilize `pip-audit` or equivalent tools to scan for known vulnerabilities in upstream packages.
