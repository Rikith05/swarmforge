"""End-to-end FastAPI REST and SSE endpoint tests."""

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from swarmforge.server import create_app


class TestSwarmForgeAPI(unittest.TestCase):
    def test_rest_and_streaming_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = create_app(db_path=Path(tmp) / "api.db", seed_demo=True)
            with TestClient(app) as client:
                home = client.get("/")
                self.assertEqual(home.status_code, 200)
                self.assertIn("SwarmForge", home.text)

                health = client.get("/api/health").json()
                self.assertEqual(health["status"], "ok")

                missions = client.get("/api/missions").json()
                self.assertGreaterEqual(len(missions["missions"]), 4)

                runs = client.get("/api/runs").json()["runs"]
                self.assertEqual(len(runs), 2)

                diff = client.get(f"/api/runs/diff/{runs[0]['run_id']}/{runs[1]['run_id']}")
                self.assertEqual(diff.status_code, 200)

                fw = client.post(
                    "/api/firewall/test",
                    json={
                        "agent_role": "red_team",
                        "tool_name": "shell_exec",
                        "arguments": {"command": "rm -rf /"},
                        "policy_mode": "strict",
                    },
                )
                self.assertEqual(fw.status_code, 200)
                self.assertEqual(fw.json()["decision"]["action"], "block")

                stream_resp = client.post(
                    "/api/runs/stream",
                    json={"mission_id": "incident-triage-synthesis", "strategy": "council_judge"},
                )
                self.assertEqual(stream_resp.status_code, 200)
                self.assertIn("event: run_event", stream_resp.text)
                self.assertIn("event: run_done", stream_resp.text)


if __name__ == "__main__":
    unittest.main()
