#!/usr/bin/env python3
"""agent_change_wrapper.py

Wrapper to enforce the agent security checklist on every agent change.

Typical usage pattern:
  1) You edit /home/node/.openclaw/openclaw.json (agents changes)
  2) Run this wrapper
  3) If validation PASS, it restarts the OpenClaw gateway

Exit codes:
  0 validation PASS and (if enabled) restart succeeded
  1 warnings-only (no restart)
  2 validation FAIL (no restart)
  3 restart failed (validation passed)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone


def run(cmd: list[str]) -> int:
    p = subprocess.run(cmd, text=True)
    return int(p.returncode)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--config",
        default="/home/node/.openclaw/openclaw.json",
        help="Path to openclaw.json to validate",
    )
    ap.add_argument(
        "--validator",
        default="skills/public/agent-security-checklist/scripts/enforce_agent_security.py",
        help="Path to validator script (relative OK)",
    )
    ap.add_argument(
        "--restart",
        action="store_true",
        default=True,
        help="Restart gateway when validation passes (default: true)",
    )
    ap.add_argument(
        "--no-restart",
        action="store_true",
        help="Do not restart gateway (validation still runs)",
    )
    ap.add_argument(
        "--reason",
        default="agent config validated by agent-security-checklist",
        help="Optional restart reason (logged)",
    )
    args = ap.parse_args()

    do_restart = bool(args.restart) and not bool(args.no_restart)

    # 1) Validate
    vcmd = [sys.executable, args.validator, "--config", args.config]
    rc = run(vcmd)

    if rc != 0:
        # 1=warnings, 2=fail according to validator; in both cases: do not restart.
        print(f"\nWRAPPER: validation did not PASS (rc={rc}); gateway restart skipped.")
        return rc

    # 2) Restart gateway
    if not do_restart:
        print("\nWRAPPER: validation PASS; --no-restart set, skipping gateway restart.")
        return 0

    print(f"\nWRAPPER: validation PASS @ {utc_now()}; restarting gateway...")

    # Use OpenClaw CLI (preferred) and keep shell=False.
    # Note: some installations accept --reason; if yours doesn't, remove it.
    restart_cmd = ["openclaw", "gateway", "restart"]
    # Try with reason first, fall back without it if unsupported.
    rc_restart = run(restart_cmd + ["--reason", args.reason])
    if rc_restart != 0:
        rc_restart = run(restart_cmd)

    if rc_restart != 0:
        print(f"WRAPPER: gateway restart failed (rc={rc_restart})")
        return 3

    print("WRAPPER: gateway restart OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
