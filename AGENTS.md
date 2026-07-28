# Repository Layout For Agents

Product code lives in `crates/`. SpecRail process tooling (specs, checks, skills, workflow/state/label definitions) lives in `tooling/specrail/` — that directory is the pack root.

Before running any SpecRail command or writing specs, read `tooling/specrail/AGENT_USAGE.md`. All `python3 checks/...` commands and relative paths in skills/docs are relative to the pack root, i.e. run them from `tooling/specrail/` (`cd tooling/specrail && python3 checks/check_workflow.py --repo . --all-specs`).
