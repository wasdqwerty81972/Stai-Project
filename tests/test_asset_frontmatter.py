"""
tests/test_asset_frontmatter.py — Asset frontmatter must survive a BOM.

Every file under subagents/definitions/ and half of skills/ is written with a
UTF-8 BOM. ``\\A---`` does not match when one precedes the delimiter, so
``split_frontmatter`` returned ``({}, whole_file)`` for 336 asset files. The
parser is deliberately forgiving, which is exactly what made the loss silent:
all 68 markdown specialists loaded with no declared tools, no model, and no
description, and then reported "Scoped analysis executed without anomaly
indicators" — a clean-looking result from a specialist that could not call a
single tool.

These tests pin the parse itself and the three registries built on top of it.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from cyber_os.assets import paths
from cyber_os.assets.agents import get_agent_definition_registry
from cyber_os.assets.frontmatter import as_list, split_frontmatter
from cyber_os.assets.skills import get_skill_registry

BOM = "﻿"


class SplitFrontmatterTests(unittest.TestCase):
    def test_a_bom_does_not_hide_the_frontmatter(self) -> None:
        doc = BOM + "---\nname: probe\ntools: Read, Grep\n---\n\nbody text\n"
        meta, body = split_frontmatter(doc)
        self.assertEqual(meta.get("name"), "probe")
        self.assertEqual(as_list(meta.get("tools")), ["Read", "Grep"])
        self.assertIn("body text", body)

    def test_parsing_is_unchanged_without_a_bom(self) -> None:
        doc = "---\nname: probe\n---\n\nbody text\n"
        meta, body = split_frontmatter(doc)
        self.assertEqual(meta.get("name"), "probe")
        self.assertIn("body text", body)

    def test_a_bom_is_stripped_from_the_body_when_there_is_no_frontmatter(self) -> None:
        meta, body = split_frontmatter(BOM + "# Just a heading\n")
        self.assertEqual(meta, {})
        self.assertFalse(body.startswith(BOM), "the BOM must not leak into the body")

    def test_a_malformed_block_still_yields_an_empty_mapping(self) -> None:
        # The forgiving contract in the module docstring must hold: one bad
        # file cannot take down discovery for the other few hundred.
        meta, body = split_frontmatter(BOM + "---\nname: [unclosed\n---\nbody\n")
        self.assertEqual(meta, {})
        self.assertIn("body", body)


class AssetFilesCarryABomTests(unittest.TestCase):
    """If the BOMs are ever normalised away, this test says so rather than
    leaving the guard above looking like it protects nothing."""

    def test_the_shipped_assets_still_exercise_the_bom_path(self) -> None:
        agent_files = sorted(Path(paths.agent_definitions_dir()).rglob("*.md"))
        self.assertTrue(agent_files, "no subagent definitions were found at all")
        with_bom = [f for f in agent_files if f.read_bytes()[:3] == b"\xef\xbb\xbf"]
        self.assertTrue(
            with_bom,
            "no definition carries a BOM any more — if they were normalised, "
            "keep SplitFrontmatterTests but this check is obsolete",
        )


class AgentDefinitionRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.definitions = get_agent_definition_registry().all()

    def test_every_definition_parsed_its_frontmatter(self) -> None:
        self.assertTrue(self.definitions, "no subagent definitions loaded")
        for definition in self.definitions:
            with self.subTest(agent=definition.name):
                self.assertTrue(
                    definition.declared_tools,
                    "declared no tools — frontmatter was not parsed",
                )
                self.assertTrue(definition.description, "no description parsed")

    def test_every_definition_has_at_least_one_usable_tool(self) -> None:
        # A specialist with an empty allowlist runs, calls nothing, and reports
        # a clean result. That is indistinguishable from a real all-clear.
        toolless = [d.name for d in self.definitions if not d.allowed_tools]
        self.assertEqual(toolless, [], "these specialists can call no tool at all")

    def test_no_definition_maps_onto_an_unregistered_tool(self) -> None:
        from cyber_tools import AuditLogger, ToolRegistry, register_all_default_tools

        registry = ToolRegistry(AuditLogger())
        register_all_default_tools(registry)
        live = set(registry.tools)
        for definition in self.definitions:
            with self.subTest(agent=definition.name):
                self.assertEqual(
                    definition.missing_tools,
                    [],
                    "translated to a tool name the registry does not answer to",
                )
                self.assertTrue(set(definition.allowed_tools) <= live)


class SkillRegistryTests(unittest.TestCase):
    def test_every_skill_parsed_a_description(self) -> None:
        skills = get_skill_registry().all()
        self.assertTrue(skills, "no skills loaded")
        undescribed = [s.name for s in skills if not s.description]
        self.assertEqual(
            undescribed,
            [],
            "a skill with no description cannot be selected by the model",
        )


if __name__ == "__main__":
    unittest.main()
