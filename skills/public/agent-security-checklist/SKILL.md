---
name: agent-security-checklist
description: Enforce an OpenClaw agent security checklist every time an agent is created, edited, or updated (openclaw.json agents.list changes). Use to define mandatory guardrails (openclaw-security regex allowlist/denylist, exec/tool permissions, messaging allowlists, elevated tool restrictions) and to run a deterministic validator that blocks unsafe agent configs.
---

# Agent Security Checklist (OpenClaw)

## Goal

Keep a **mandatory, repeatable** security checklist for OpenClaw agents, and fail fast when an agent is created/updated with unsafe permissions.

This skill provides:
- A **written checklist** (reference file)
- A **validator script** that audits `/home/node/.openclaw/openclaw.json`

## Use

After *any* agent change (new agent, tools/profile changes, messaging bindings, elevated, exec permissions):

1) Run:

```bash
python3 skills/public/agent-security-checklist/scripts/enforce_agent_security.py --config /home/node/.openclaw/openclaw.json
```

2) If it reports failures, fix config and re-run until clean.

### Make it run “every time” (practical automation options)

Pick one:

- **Option A (recommended): Git gate**
  - If `openclaw.json` is managed in git, run the validator in CI and/or a pre-commit hook.

- **Option B: Scheduled gate (cron)**
  - Run the validator periodically and alert if it fails.

- **Option C: Wrapper command**
  - Always modify agents through a wrapper script that runs the validator before `gateway restart`.

(If you want *true* lifecycle hooks inside OpenClaw on agent create/update, that requires a dedicated plugin/hook point; treat this skill as the enforcement layer and the script as the policy engine.)

## What to check

Read the canonical checklist:
- `references/checklist.md`

## Script behavior

- Exits **0** on pass
- Exits **2** on hard failures
- Exits **1** on warnings-only

Output is human-readable and designed to be used in CI.
