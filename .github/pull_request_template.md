## Summary
Describe what changed in the orchestrator, policy firewall, tools, evals, or studio UI.

## Verification Checklist
- [ ] `python -m unittest discover -s tests -v` (or `pytest -v`) passes
- [ ] `node --check` passes on modified `swarmforge/web/*.js`
- [ ] `swarmforge eval --strict` passes with 100% Council+Judge pass rate
- [ ] `swarmforge scan .` passes cleanly
