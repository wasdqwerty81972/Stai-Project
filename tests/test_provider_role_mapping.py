import unittest
from pathlib import Path



class ProviderRoleMappingTests(unittest.TestCase):
    def test_investigator_role_uses_a_defined_provider_slot(self) -> None:
        """The default CyberAgent orchestration role must be routable by AiApi."""
        root = Path(__file__).parents[1]
        agent_source = (root / "cyber_agent.py").read_text(encoding="utf-8")
        provider_source = (root / "key_manager.py").read_text(encoding="utf-8")
        self.assertIn('"investigator": "You are a senior security investigator.', agent_source)
        self.assertIn('"investigator": 0,', provider_source)
