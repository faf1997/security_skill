# OpenClaw Agent Security Checklist (mandatory)

This checklist applies whenever you:
- Add an agent to `agents.list`
- Change an agent `tools.profile` / `alsoAllow`
- Enable/modify `tools.elevated`
- Add/modify messaging bindings or channel allowlists
- Change `plugins.entries.openclaw-security.config`

## 1) Exec policy (openclaw-security)

- `plugins.entries.openclaw-security.enabled = true`
- `plugins.entries.openclaw-security.config.exec.enabled = true`
- `defaultPolicy` must be **denylist** with at least meta-character blocking (prevent chaining / injection):
  - deny: `[;&|`$<>\n\r]`

### If an agent is allowed to use `exec`

If an agent has `tools.alsoAllow` containing `"exec"`:
- There MUST be an agent-specific policy at:
  - `plugins.entries.openclaw-security.config.exec.policies[agentId]`
- That policy MUST be **allowlist mode**
- That policy MUST have:
  - a non-empty `allow` list
  - a deny entry blocking `[;&|`$<>\n\r]`

Rule of thumb:
- Only allow **atomic commands** (no `;`, `&&`, pipes, redirects, backticks, `$()`)
- Prefer a single-purpose runner (shell=false) as the next step beyond regex

## 2) Tool minimization (per agent)

- Default: no `exec`, no `elevated`
- `tools.profile` should be the minimal viable profile
- If `exec` is present, ensure the agent has a tight messaging posture (see below)

## 3) Elevated policy

If `tools.elevated.enabled = true`:
- Must have an **allowlist** origin (`allowFrom`) that is not `*`
- Must be restricted to explicit channel+sender identities

## 4) Messaging exposure

For channels/accounts bound to agents that can `exec` or are otherwise high-risk:
- Prefer `dmPolicy=allowlist`
- `allowFrom` must not be `*`
- `groupPolicy` should be disabled unless you have a strong reason

## 5) Agent inventory sanity

- Every agent in `agents.list` has:
  - stable `id`
  - explicit `workspace` if it should be isolated
- No duplicate/overlapping broad bindings that could route untrusted messages into a privileged agent

## 6) Non-bypass rule (coordination)

- If an agent cannot do something itself, it must not be able to cause another agent to do it indirectly.
- For privileged “Runner” agents, accept only **intent-based** requests, not raw shell commands.
