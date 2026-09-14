from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class EmailValidatorTool(CyberToolPlugin):
    name = "email_validator"
    description = "Validate email syntax and check MX records."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import re
        import dns.resolver
        email = arguments.get("email", "")
        if not email:
            return {"success": False, "output": {}, "error": "Missing 'email' argument."}
        syntax_valid = bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))
        domain = email.split("@")[-1] if "@" in email else ""
        mx_records = []
        try:
            if domain:
                answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
                mx_records = [str(r).split()[1].rstrip('.') for r in answers]
        except Exception:
            pass
        return {
            "success": True,
            "output": {"email": email, "syntax_valid": syntax_valid, "domain": domain, "mx_records": mx_records, "deliverable": syntax_valid and bool(mx_records)},
            "error": "" if syntax_valid else "Invalid email syntax.",
        }


TOOL_CLASS = EmailValidatorTool
