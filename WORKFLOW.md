---
repo_backlog:
  enabled: true
  poll_interval_secs: 900
  batch_limit: 128
runtime_dispatch:
  enabled: true
  interval_secs: 30
  batch_limit: 32
  approval_policy: never
  timeout_secs: 3600
  activity_profiles:
    plan_repo_sprint:
      reasoning_effort: xhigh
    poll_repo_backlog:
      runtime_kind: codex_exec
      runtime_profile: codex-backlog-exec
      reasoning_effort: low
runtime_worker:
  enabled: true
  interval_secs: 5
  concurrency: 20
  lease_ttl_secs: 600
runtime_retry_policy:
  max_failed_activity_retries: 2
  retry_delay_secs: 20
  max_retry_delay_secs: 180
  activity_retries: {}
---

Harness runtime policy for automated backlog scanning.
