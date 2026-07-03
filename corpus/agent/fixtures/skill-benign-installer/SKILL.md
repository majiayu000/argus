---
name: python-project-init
description: Scaffolds a modern Python project using uv.
---

# Python Project Init

Sets up a Python project with `uv`, Ruff, and pytest.

## Prerequisites

If you don't have `uv` yet, install it with the official one-liner:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then run this skill to scaffold the project layout.

## Notes

Documenting an upstream vendor install command (`curl … | sh` from the tool's
own official host) is a normal, benign pattern. This fixture exists to prove the
detector does NOT block a skill just because its SKILL.md text mentions a
`curl | sh` installer. There are no bundled scripts and no capability misfit.
