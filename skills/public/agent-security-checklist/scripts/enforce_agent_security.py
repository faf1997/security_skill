#!/usr/bin/env python3
"""enforce_agent_security.py

Deterministic validator for OpenClaw agent security posture.

Exit codes:
  0 pass
  1 warnings only
  2 failures

This script is intentionally conservative: it prefers flagging risk over guessing intent.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


DENY_META_DEFAULT = r"[;&|`$<>\n\r]"


@dataclass
class Finding:
    level: str  # FAIL | WARN
    code: str
    message: str
    path: str


def jget(obj: Any, path: List[str], default=None):
    cur = obj
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def has_exec(agent: Dict[str, Any]) -> bool:
    also = jget(agent, ["tools", "alsoAllow"], [])
    return isinstance(also, list) and "exec" in also


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/home/node/.openclaw/openclaw.json")
    args = ap.parse_args()

    cfg_path = args.config
    if not os.path.exists(cfg_path):
        print(f"FAIL E_CFG_MISSING config not found: {cfg_path}")
        return 2

    try:
        cfg = load_json(cfg_path)
    except Exception as e:
        print(f"FAIL E_CFG_PARSE could not parse JSON: {e}")
        return 2

    findings: List[Finding] = []

    # --- plugin presence ---
    sec_enabled = bool(jget(cfg, ["plugins", "entries", "openclaw-security", "enabled"], False))
    if not sec_enabled:
        findings.append(Finding("FAIL", "E_SEC_DISABLED", "plugins.entries.openclaw-security.enabled must be true", "plugins.entries.openclaw-security.enabled"))

    exec_enabled = bool(jget(cfg, ["plugins", "entries", "openclaw-security", "config", "exec", "enabled"], False))
    if not exec_enabled:
        findings.append(Finding("FAIL", "E_EXEC_GUARD_DISABLED", "openclaw-security exec guard must be enabled", "plugins.entries.openclaw-security.config.exec.enabled"))

    # --- default meta-char deny ---
    default_mode = jget(cfg, ["plugins", "entries", "openclaw-security", "config", "exec", "defaultPolicy", "mode"], None)
    default_deny = jget(cfg, ["plugins", "entries", "openclaw-security", "config", "exec", "defaultPolicy", "deny"], [])

    if default_mode != "denylist":
        findings.append(Finding("FAIL", "E_DEFAULT_MODE", "defaultPolicy.mode should be 'denylist'", "plugins.entries.openclaw-security.config.exec.defaultPolicy.mode"))

    if not (isinstance(default_deny, list) and any(d == DENY_META_DEFAULT for d in default_deny)):
        findings.append(Finding(
            "FAIL",
            "E_DEFAULT_DENY_META",
            f"defaultPolicy.deny must include meta-character block regex: {DENY_META_DEFAULT}",
            "plugins.entries.openclaw-security.config.exec.defaultPolicy.deny",
        ))

    # --- agent rules ---
    agents = jget(cfg, ["agents", "list"], [])
    if not isinstance(agents, list) or not agents:
        findings.append(Finding("FAIL", "E_AGENTS_EMPTY", "agents.list must be a non-empty array", "agents.list"))
        agents = []

    policies = jget(cfg, ["plugins", "entries", "openclaw-security", "config", "exec", "policies"], {})
    if not isinstance(policies, dict):
        policies = {}

    # Channel posture (global + per-account) warnings for privileged agents
    telegram_global_allow = jget(cfg, ["channels", "telegram", "allowFrom"], None)
    whatsapp_global_allow = jget(cfg, ["channels", "whatsapp", "allowFrom"], None)

    for agent in agents:
        if not isinstance(agent, dict):
            continue
        agent_id = agent.get("id")
        if not agent_id or not isinstance(agent_id, str):
            findings.append(Finding("FAIL", "E_AGENT_ID", "agent id missing or invalid", "agents.list[].id"))
            continue

        exec_ok = has_exec(agent)

        # If exec is allowed, there must be a strict allowlist policy.
        if exec_ok:
            pol = policies.get(agent_id)
            if not isinstance(pol, dict):
                findings.append(Finding("FAIL", "E_AGENT_EXEC_NO_POLICY", f"agent '{agent_id}' allows exec but has no openclaw-security policy", f"plugins.entries.openclaw-security.config.exec.policies.{agent_id}"))
            else:
                mode = pol.get("mode")
                allow = pol.get("allow")
                deny = pol.get("deny")

                if mode != "allowlist":
                    findings.append(Finding("FAIL", "E_AGENT_EXEC_MODE", f"agent '{agent_id}' exec policy must be allowlist", f"...policies.{agent_id}.mode"))

                if not (isinstance(allow, list) and len(allow) > 0):
                    findings.append(Finding("FAIL", "E_AGENT_EXEC_ALLOW_EMPTY", f"agent '{agent_id}' allowlist must be non-empty", f"...policies.{agent_id}.allow"))

                if not (isinstance(deny, list) and any(d == DENY_META_DEFAULT for d in deny)):
                    findings.append(Finding("FAIL", "E_AGENT_EXEC_DENY_META", f"agent '{agent_id}' deny must include meta-character block: {DENY_META_DEFAULT}", f"...policies.{agent_id}.deny"))

                # Heuristic: forbid overly-broad allow patterns
                if isinstance(allow, list):
                    for i, pat in enumerate(allow):
                        if not isinstance(pat, str):
                            continue
                        if pat.strip() in (".*", "^.*$", "^.*"):
                            findings.append(Finding("FAIL", "E_AGENT_EXEC_ALLOW_BROAD", f"agent '{agent_id}' has overly broad allow regex at index {i}", f"...policies.{agent_id}.allow[{i}]"))
                        # Try compiling regex if configured to block on error; we still validate here.
                        try:
                            re.compile(pat, flags=re.IGNORECASE)
                        except re.error as e:
                            findings.append(Finding("FAIL", "E_AGENT_EXEC_BAD_REGEX", f"agent '{agent_id}' has invalid allow regex: {e}", f"...policies.{agent_id}.allow[{i}]"))

            # Messaging posture warnings
            # If global allowFrom is '*', warn (depends on your deployment intent).
            if telegram_global_allow == ["*"] or telegram_global_allow == "*":
                findings.append(Finding("WARN", "W_TG_GLOBAL_OPEN", f"telegram global allowFrom is open while agent '{agent_id}' has exec", "channels.telegram.allowFrom"))
            if whatsapp_global_allow == ["*"] or whatsapp_global_allow == "*":
                findings.append(Finding("WARN", "W_WA_GLOBAL_OPEN", f"whatsapp global allowFrom is open while agent '{agent_id}' has exec", "channels.whatsapp.allowFrom"))

        # Elevated restrictions
        elev_enabled = bool(jget(agent, ["tools", "elevated", "enabled"], False))
        if elev_enabled:
            allow_from = jget(agent, ["tools", "elevated", "allowFrom"], None)
            if allow_from is None:
                findings.append(Finding("FAIL", "E_ELEV_ALLOWFROM_MISSING", f"agent '{agent_id}' elevated enabled but allowFrom missing", f"agents.list[{agent_id}].tools.elevated.allowFrom"))
            else:
                # Reject '*' anywhere
                dumped = json.dumps(allow_from)
                if "*" in dumped:
                    findings.append(Finding("FAIL", "E_ELEV_ALLOWFROM_WILDCARD", f"agent '{agent_id}' elevated allowFrom must not contain '*'", f"agents.list[{agent_id}].tools.elevated.allowFrom"))

    # Print report
    fails = [f for f in findings if f.level == "FAIL"]
    warns = [f for f in findings if f.level == "WARN"]

    for f in findings:
        print(f"{f.level} {f.code} {f.message} ({f.path})")

    if fails:
        print(f"\nRESULT: FAIL ({len(fails)} failures, {len(warns)} warnings)")
        return 2
    if warns:
        print(f"\nRESULT: WARN ({len(warns)} warnings)")
        return 1

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
