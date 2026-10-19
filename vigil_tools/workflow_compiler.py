#!/usr/bin/env python3
"""
Workflow Compiler for STAI 2 Cybersecurity Agent

Adapted from Vigil SOC workflow system.
Compiles Markdown-style workflow definitions into executable playbooks.

Usage:
    python vigil_tools/workflow_compiler.py --list
    python vigil_tools/workflow_compiler.py --compile incident-response
    python vigil_tools/workflow_compiler.py --validate my-workflow.md
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

# YAML-like front matter parser (no PyYAML dependency)
def parse_front_matter(text: str) -> Dict[str, Any]:
    """Parse YAML-like front matter from markdown."""
    if not text.startswith("---"):
        return {}
    end = text.find("---", 3)
    if end == -1:
        return {}
    front = text[3:end].strip()
    result: Dict[str, Any] = {}
    for line in front.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if value.lower() == "true":
                result[key] = True
            elif value.lower() == "false":
                result[key] = False
            else:
                result[key] = value
    return result


def parse_phase_block(text: str) -> List[Dict[str, Any]]:
    """Parse phase blocks from workflow markdown."""
    phases = []
    pattern = re.compile(
        r'- id:\s*(\S+)\s*'
        r'name:\s*"([^"]+)"\s*'
        r'agent:\s*(\S+)\s*'
        r'tools:\s*\[([^\]]+)\]\s*'
        r'(?:approval_required:\s*(true|false))?',
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        tools = [t.strip().strip('"').strip("'") for t in match.group(4).split(",")]
        phases.append({
            "id": match.group(1),
            "name": match.group(2),
            "agent": match.group(3),
            "tools": tools,
            "approval_required": match.group(5) == "true" if match.group(5) else False,
        })
    return phases


def compile_workflow(markdown_text: str) -> Dict[str, Any]:
    """Compile a workflow markdown file into an executable playbook."""
    front = parse_front_matter(markdown_text)
    body = markdown_text.split("---", 2)[-1] if "---" in markdown_text else markdown_text
    phases = parse_phase_block(markdown_text)

    return {
        "name": front.get("name", "unnamed"),
        "description": front.get("description", ""),
        "use_case": front.get("use_case", ""),
        "phases": phases,
        "raw": markdown_text,
    }


def validate_workflow(markdown_text: str) -> List[str]:
    """Validate a workflow definition. Returns list of errors."""
    errors = []
    playbook = compile_workflow(markdown_text)
    if not playbook["phases"]:
        errors.append("Workflow has no phases defined")
    for i, phase in enumerate(playbook["phases"]):
        if not phase.get("id"):
            errors.append(f"Phase {i+1} missing id")
        if not phase.get("agent"):
            errors.append(f"Phase {i+1} ({phase.get('name', '?')}) missing agent")
        if not phase.get("tools"):
            errors.append(f"Phase {i+1} ({phase.get('name', '?')}) has no tools")
    return errors


def list_builtin_workflows() -> List[str]:
    """List available built-in workflow names."""
    return ["incident-response", "threat-hunt", "forensic-analysis"]


def main():
    parser = argparse.ArgumentParser(description="Compile and validate SOC workflows")
    parser.add_argument("--compile", type=str, help="Compile a built-in workflow by name")
    parser.add_argument("--validate", type=Path, help="Validate a workflow markdown file")
    parser.add_argument("--list", action="store_true", help="List built-in workflows")
    parser.add_argument("--file", type=Path, help="Compile a workflow from a markdown file")
    args = parser.parse_args()

    if args.list:
        workflows = list_builtin_workflows()
        print("Built-in workflows:")
        for w in workflows:
            print(f"  - {w}")
    elif args.compile:
        # Import from cyber_agent
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from cyber_agent import BUILTIN_WORKFLOWS
        if args.compile in BUILTIN_WORKFLOWS:
            wf = BUILTIN_WORKFLOWS[args.compile]
            output = {
                "name": wf.name,
                "description": wf.description,
                "phases": [
                    {
                        "id": p.id,
                        "name": p.name,
                        "agent": p.agent,
                        "tools": p.tools,
                        "approval_required": p.approval_required,
                    }
                    for p in wf.phases
                ],
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"Workflow '{args.compile}' not found.")
    elif args.validate:
        text = args.validate.read_text(encoding="utf-8")
        errors = validate_workflow(text)
        if errors:
            print("Validation errors:")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print("Workflow is valid.")
    elif args.file:
        text = args.file.read_text(encoding="utf-8")
        playbook = compile_workflow(text)
        print(json.dumps(playbook, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
