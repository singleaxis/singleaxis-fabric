# Deployment postures, not regulatory profiles

Recorder v1 ships two technical Helm postures:

| Profile | Purpose | Production claim |
|---|---|---|
| `shadow-dev` | Local evaluation and integration development | None |
| `shadow-production` | Fail-closed passive recorder configuration | Technical posture only; not certification |

Recorder v1 does not ship assurance tiers, industry policy packs, legal
mappings, or profiles claiming compliance with HIPAA, the EU AI Act, financial
services rules, or any other regime.

`shadow-production` pins export minimization, authenticated ingress and egress,
explicit network peers, durable queueing, and retry behavior. These are useful
controls in regulated environments, but they do not establish lawful basis,
data minimization, retention, human oversight, model validation, or incident
governance for a specific use case.

Regulatory mappings and approved deployment templates belong in a governed
management plane where they can be versioned, reviewed, approved, and bound to
a customer deployment. They may configure the open recorder, but they are not
part of its public runtime or default package.
