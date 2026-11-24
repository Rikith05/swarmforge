"""Tests for real AST, security sink, dependency, prompt, and diff tools."""

import unittest
from pathlib import Path

from swarmforge.tools.fixtures import get_mission_definition
from swarmforge.tools.registry import ToolRegistry


class TestToolRegistry(unittest.TestCase):
    def test_agent_pipeline_fixture_audits(self) -> None:
        mission = get_mission_definition("agent-security-audit")
        reg = ToolRegistry(virtual_files=mission["virtual_files"])

        inv = reg.execute("workspace_inventory", {})
        self.assertTrue(inv["ok"])
        self.assertEqual(inv["file_count"], 3)

        ast_res = reg.execute("ast_complexity_scan", {})
        self.assertGreaterEqual(ast_res["python_files_parsed"], 2)
        self.assertTrue(any(r["code"] == "UNBOUNDED_WHILE_TRUE" for r in ast_res["loop_risks"]))

        sink_res = reg.execute("secret_and_sink_audit", {})
        codes = set(sink_res["finding_codes"])
        self.assertTrue({"HARDCODED_SECRET", "UNSAFE_SHELL", "UNSAFE_DESERIALIZATION", "DYNAMIC_EVAL", "SQL_INTERPOLATION"}.issubset(codes))

        prompt_res = reg.execute("prompt_surface_auditor", {})
        prompt_codes = set(prompt_res["finding_codes"])
        self.assertIn("PROMPT_INJECTION_SURFACE", prompt_codes)
        self.assertIn("OVERPRIVILEGED_MCP_TOOL", prompt_codes)

        patch_res = reg.execute("patch_synthesizer", {})
        self.assertGreaterEqual(patch_res["patch_count"], 1)
        self.assertIn("--- a/agent_gateway.py", patch_res["patches"][0]["diff"])

    def test_real_directory_scan_on_swarmforge(self) -> None:
        repo_root = Path(__file__).resolve().parents[1] / "swarmforge"
        reg = ToolRegistry(target_path=str(repo_root))
        inv = reg.execute("workspace_inventory", {})
        self.assertGreater(inv["file_count"], 5)

        dep = reg.execute("dependency_graph_mapper", {})
        self.assertGreater(dep["module_count"], 5)
        self.assertGreater(dep["total_import_edges"], 5)

        ast_res = reg.execute("ast_complexity_scan", {})
        self.assertGreater(ast_res["function_count"], 10)


if __name__ == "__main__":
    unittest.main()
