# Threads Integration

SpecRail can work with a threads-style orchestration skill, but it must not
depend on one. SpecRail owns the repository workflow contract. A threads skill
owns execution orchestration when work needs parallel lanes, queue gates,
review gates, or closure audits.

## Principle

- SpecRail is the policy and artifact layer.
- Threads is the optional execution layer.
- SpecRail checks run before thread dispatch and again before completion.
- Missing thread support falls back to the normal single-agent SpecRail flow
  only after the fallback and reason are recorded.
- Stable machine-facing IDs stay unchanged across integrations and locales.
- Large logs and raw tool output are artifacts, not parent-thread state.

## When To Use Threads

Use an available threads skill after SpecRail preflight when the task involves:

- a GitHub issue or pull request queue
- multiple independent implementation lanes
- read-only planner or reviewer lanes
- review thread, CI, or merge-readiness closure
- long-running work that needs a durable handoff

Do not use threads for a small single-file change, ordinary spec drafting, or
any task where all writable files overlap.

## Execution Order

1. Run SpecRail preflight.
   - Load `AGENTS.md`, `workflow.yaml`, `states.yaml`, `labels.yaml`, relevant
     templates, and `skills/specrail-workflow/SKILL.md`.
   - Select the locale.
   - Identify the route, required artifacts, human gates, and verification
     commands.
2. If the task needs queue or parallel orchestration, load the threads skill.
3. Run the threads capability and queue gates.
   - Confirm whether native subagents are available.
   - Record `thread_dispatch_gate` before implementation, review, push, or
     merge work.
   - Fetch remote truth for GitHub queues.
   - Map issues to existing PRs before opening new work.
   - Build a lane map with disjoint writable files.
4. Execute lanes.
   - Planners and reviewers are read-only.
   - Workers own explicit writable paths.
   - The coordinator owns shared verification and final synthesis.
   - Large command output goes to artifact files; parent context receives only
     exit code, short tail, targeted grep, and artifact paths.
5. Run SpecRail verification.
   - Validate the pack.
   - Validate the spec packet when a spec changed.
   - Preserve human-facing locale rules.
6. Run threads closure audit when GitHub queue or PR state changed.
   - Re-check PR heads, CI, review threads, merge state, and issue closure.
   - Separate remote truth from local worktree state.

For GitHub PR merge work, native thread dispatch is mandatory when native
subagents are available. A PR must have at least one independent read-only
`reviewer` or `merge_reviewer` native lane before merge readiness can be
reported. The coordinator lane is not a native reviewer, even when it performs
the final synthesis.

## Handoff Contract

Agents should record this block when both systems are active:

```yaml
specrail_threads_handoff:
  specrail:
    route:
    current_state:
    selected_locale:
    required_artifacts:
    human_gates:
    verification_commands:
  threads:
    mode:
    truth_level:
    thread_dispatch_gate:
    queue_ledger:
    issue_to_pr_map:
    lanes:
    merge_policy:
    stop_conditions:
    context_budget:
    output_firewall:
  checkpoint:
    path:
    runtime_gate:
```

The block is a handoff artifact, not a schema-stable API. A future evaluator can
turn it into a validated artifact after repeated real use.

## Approved-Spec Implementation Queue

When the route is `implement` and several approved specs are ready, use
`skills/specrail-implement-queue/SKILL.md` before dispatching threads.

The queue skill owns the SpecRail side of the plan:

- issue to spec mapping
- existing PR detection
- partial versus final PR closing semantics
- acceptance criteria coverage
- required deterministic checks
- human gates and merge authorization

Threads owns the orchestration side:

- native subagent availability
- queue ledger
- lane map and writable ownership
- read-only planner and reviewer lanes
- native reviewer or merge-reviewer evidence when merge work is in scope
- CI polling and review-thread checks
- closure audit after PR or issue state changes
- parent context budget and output firewall enforcement

Record this queue handoff when both systems are active:

```yaml
specrail_implementation_queue:
  issues:
    - issue:
      spec_dir:
      existing_prs:
      planned_prs:
      completion_mode: partial | final
      acceptance_evidence:
  orchestration:
    threads_mode:
    lanes:
    thread_dispatch_gate:
    native_thread_evidence:
    fallback_reason:
    context_budget:
    output_firewall:
  checkpoint:
    path:
    runtime_gate:
  gates:
    route_gate:
    pr_gate:
    review_threads:
    merge_authorization:
```

This handoff must not grant approval or merge authority. It only preserves the
evidence each system needs.

## Field Mapping

| SpecRail field | Threads field | Notes |
| --- | --- | --- |
| `route` | `intent_contract.goal` | The route defines the kind of workflow action. |
| `required_artifacts` | `queue_ledger.acceptance_evidence` | Threads records evidence for each queue item. |
| `human_gates` | `merge_policy`, `stop_conditions` | Threads must not bypass SpecRail gates. |
| `verification_commands` | `verification_owner` | One owner runs shared checks for a tranche. |
| `selected_locale` | final report language | Human-facing reports follow SpecRail locale rules. |
| runtime checkpoint | `queue_ledger`, `threads_run_log` | Checkpoints are local handoff artifacts; run logs are observational. |

## Long-Run Guardrails

For long queues, use these defaults unless the user or runtime provides a
stricter budget:

- soft stop at 50% of the active context window
- hard stop at 65%
- critical stop at 75%

At hard stop, write or update the runtime checkpoint and hand off to a fresh
parent thread. At critical stop, do not spawn lanes or read large outputs; write
checkpoint and resume instructions only.

Do not load raw Codex session JSONL or old parent transcripts as live queue
state. Use SpecRail artifacts, runtime checkpoints, repo-local compact run logs,
and fresh GitHub truth.

Large output commands must use an artifact-first pattern:

```bash
cargo test --all-features --locked > artifacts/logs/<tranche>/cargo-test.log 2>&1
tail -n 150 artifacts/logs/<tranche>/cargo-test.log
```

Avoid broad searches under `.codex`, `.claude`, `target`, `node_modules`,
session JSONL, or log files.

For re-review after fixes, prefer messaging or resuming the existing reviewer
lane over spawning a new fork: a fork replays the full lane history each round
and multiplies token cost per round. When the runtime cannot resume a lane,
spawn a fresh lane scoped to the diff since the previously reviewed head
(`review_mode: diff_only`) plus the prior-findings checklist, instead of a new
full-history review. See Review Rounds And Modes in
`skills/specrail-review-pr/SKILL.md`.

## Fallback

If no threads skill or native subagent capability is available, the agent should
continue with the normal SpecRail flow and say that no native threads were
launched. If the user explicitly requested threads, the agent may provide a
prompt pack and lane map instead of pretending parallel execution happened.

If native subagents are available and the work includes PR review or merge, do
not use single-agent fallback unless the user explicitly forbids spawning or the
checkpoint records a concrete `no_spawn_reason` that makes native dispatch
unsafe. Such a fallback cannot be reported as full threads execution.

## Non-Goals

- Do not vendor a local threads skill into SpecRail.
- Do not make threads required for adoption.
- Do not let threads override SpecRail policy, locale, or human gates.
- Do not add automatic merge or final approval.
- Do not require GitHub for repositories that use SpecRail without GitHub.

## Minimal Agent Rule

For agents such as Codex:

```text
Run SpecRail first. If the task is a queue, parallel-lane, review-thread,
merge-gate, or closure-audit problem and a threads skill is available, use
threads after SpecRail preflight. SpecRail owns policy; threads owns
orchestration. Return to SpecRail verification before reporting completion.
```
