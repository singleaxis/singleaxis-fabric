# Payments API incident runbook (excerpt)

## OOM after deploy
If `payments-api` is OOM-killed within ~60s of a deploy, the usual cause is
a feature flag that enables a memory-heavy code path. Steps:

1. Confirm the kill in `deploy.log` (`oom-kill` / `status=9/KILL`).
2. Identify the flag flipped in that release (here: `NEW_PRICING_ENGINE`).
3. Disable the flag, redeploy, and watch the cgroup memory for 5 minutes.
4. If memory still climbs, capture a heap profile before the next restart.

Rollback alone restores service but the flag remains armed for the next
deploy — the incident report must record the flag name and the memory
slope so the next on-call does not repeat the investigation.
