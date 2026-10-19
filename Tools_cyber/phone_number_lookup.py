from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class PhoneNumberLookupTool(CyberToolPlugin):
    name = "phone_number_lookup"
    description = "Infer country and formatting details from a phone number."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        number = arguments.get("number", "")
        if not number:
            return {"success": False, "output": {}, "error": "Missing 'number' argument."}
        digits = "".join(ch for ch in number if ch.isdigit())
        length = len(digits)
        likely_country = "Unknown"
        if length == 10 and digits.startswith("1"):
            likely_country = "US/Canada"
        elif length >= 10 and length <= 13:
            likely_country = "International"
        return {"success": True, "output": {"number": number, "digits": digits, "length": length, "likely_country": likely_country}, "error": ""}


TOOL_CLASS = PhoneNumberLookupTool
