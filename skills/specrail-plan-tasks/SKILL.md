---
name: specrail-plan-tasks
description: Use when turning an approved SpecRail product and technical spec into the numbered `tasks.md` plan. Creates stable task IDs, owners, done-when conditions, verification commands, dependencies, and handoff notes without implementing the tasks.
---

# SpecRail Plan Tasks

Use this skill to create or update the task plan before implementation.

## Steps

1. Read `specs/GH<issue-number>/product.md` and
   `specs/GH<issue-number>/tech.md`.
2. Read `templates/<locale>/tasks.md` or `templates/tasks.md`.
3. Run the implementation route gate when available:

```sh
python3 checks/route_gate.py --repo . --route implement --issue <issue-number> --state ready_to_implement --json
```

4. Write `specs/GH<issue-number>/tasks.md`.
5. Use stable task IDs such as `SP<issue-number>-T1`.
6. Collect every `B-xxx` invariant from `product.md`, then map each one to at
   least one implementation or verification task using `Covers: B-xxx`.
7. For every task, include owner, dependencies, done-when evidence, verify
   commands, and its `Covers:` field.
8. Separate implementation tasks from verification and handoff notes.

## Invariant coverage

- The union of task `Covers:` fields must include every `B-xxx` in
  `product.md`; a missing ID blocks completion of the task plan.
- A task may cover several invariants, and an invariant may require several
  tasks. Keep the mapping explicit on each affected task.
- Use `Covers: none` only for infrastructure or housekeeping that implements
  no product invariant, and include a concrete reason on the same task.
- Boundary-checklist N/A verdicts have no `B-xxx` IDs and therefore need no
  task mapping. Never invent an ID only to make the coverage sets match.
- Before finishing, compare the product ID set with the task coverage union
  and report both sets in the handoff when any mismatch remains.

## Boundaries

- Do not implement while planning tasks.
- Do not remove human gates for readiness, spec approval, final review, merge,
  release, or security decisions.
- Do not mark a task plan complete while a product invariant is absent from
  the task coverage union.
- Keep the plan small enough for one agent or a clearly partitioned thread lane.
