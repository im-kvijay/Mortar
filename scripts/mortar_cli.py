#!/usr/bin/env python3
"""thin wrapper around main.py with profile presets"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON = sys.executable or "python3"


PROFILE_PRESETS: Dict[str, Dict[str, object]] = {
    "fast": {
        "description": "disable moa/v3/a2a/ace, auto workers",
        "flags": ["--no-moa", "--no-v3", "--no-a2a", "--no-ace"],
        "env": {
            "VERIFICATION_WORKERS": "0",
            "ATTACK_WORKERS": "0",
            "ENABLE_ADVERSARIAL_ENGINE": "0",
            "BACKEND": "openrouter",
        },
    },
    "balanced": {
        "description": "default production stack",
        "flags": [],
        "env": {
            "VERIFICATION_WORKERS": "0",
            "ATTACK_WORKERS": "0",
            "ENABLE_ADVERSARIAL_ENGINE": "1",
            "BACKEND": "openrouter",
        },
    },
    "full": {
        "description": "same as balanced",
        "flags": [],
        "env": {
            "VERIFICATION_WORKERS": "0",
            "ATTACK_WORKERS": "0",
            "ENABLE_ADVERSARIAL_ENGINE": "1",
            "BACKEND": "openrouter",
        },
    },
}


def build_command(args: argparse.Namespace) -> List[str]:
    cmd = [PYTHON, os.path.join(PROJECT_ROOT, "main.py")]
    if getattr(args, "dvd", None):
        cmd.extend(["--dvd", str(args.dvd)])
    elif getattr(args, "contract", None):
        cmd.extend(["--contract", args.contract])

    cmd.extend(["--model", args.model])
    cmd.extend(["--grok-effort", args.grok_effort])
    cmd.extend(["--output-format", args.output_format])

    if args.no_jit:
        cmd.append("--no-jit")
    if args.no_poc:
        cmd.append("--no-poc")
    if args.no_verification:
        cmd.append("--no-verification")
    if args.no_sniper:
        cmd.append("--no-sniper")
    if args.no_dedup:
        cmd.append("--no-dedup")
    if args.cold_kb:
        cmd.append("--cold-kb")

    return cmd


def apply_profile_args(cmd: List[str], env: Dict[str, str], profile: str) -> None:
    preset = PROFILE_PRESETS.get(profile)
    if not preset:
        raise ValueError(f"Unknown profile '{profile}'")
    cmd.extend(preset.get("flags", []))
    env.update({k: str(v) for k, v in preset.get("env", {}).items()})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mortar-C runner with simplified profiles."
    )
    parser.add_argument("--profile", choices=list(PROFILE_PRESETS.keys()), default="balanced", help="run profile")
    parser.add_argument("--model", default="x-ai/grok-4.1-fast", help="llm model")
    parser.add_argument("--grok-effort", choices=["low", "high"], default="high", help="reasoning effort")
    parser.add_argument("--enable-adversarial", action="store_true", help="force enable adversarial engine")
    parser.add_argument("--no-jit", action="store_true", help="disable jit research")
    parser.add_argument("--no-poc", action="store_true", help="skip poc generation")
    parser.add_argument("--no-verification", action="store_true", help="skip verification layer")
    parser.add_argument("--no-sniper", action="store_true", help="disable sniper pre-filter")
    parser.add_argument("--no-dedup", action="store_true", help="disable dedup layer")
    parser.add_argument("--cold-kb", action="store_true", help="single cold pass")
    parser.add_argument("--no-baseline", action="store_true", help="skip automatic cold baseline")
    parser.add_argument("--output-format", "-f", type=str, choices=["text", "json", "sarif", "markdown"], default="text", help="output format")
    parser.add_argument("--dry-run", action="store_true", help="print command without executing")
    parser.add_argument("--list-profiles", action="store_true", help="show available profiles")
    subparsers = parser.add_subparsers(dest="mode")

    dvd_parser = subparsers.add_parser("dvd", help="run dvd level")
    dvd_parser.add_argument("dvd", type=int, choices=range(1, 19), metavar="N", help="challenge 1-18")
    contract_parser = subparsers.add_parser("contract", help="audit solidity file")
    contract_parser.add_argument("contract", help="contract path")

    args = parser.parse_args()
    if args.cold_kb:
        args.no_baseline = True
    return args


def list_profiles() -> None:
    print("Available profiles:")
    for name, preset in PROFILE_PRESETS.items():
        print(f"  {name:<9} {preset.get('description', '')}")


def main() -> None:
    args = parse_args()
    if args.list_profiles:
        list_profiles()
        return
    if not args.mode:
        raise SystemExit("error: mode (dvd|contract) required unless --list-profiles is used")

    env = os.environ.copy()
    cmd = build_command(args)
    apply_profile_args(cmd, env, args.profile)
    if args.enable_adversarial:
        env["ENABLE_ADVERSARIAL_ENGINE"] = "1"
    if "XAI_API_KEY" not in env and "OPENROUTER_API_KEY" in env:
        env["XAI_API_KEY"] = env["OPENROUTER_API_KEY"]

    def env_overrides() -> Dict[str, str]:
        keys = ("VERIFICATION_WORKERS", "ATTACK_WORKERS")
        return {k: env[k] for k in keys if k in env}

    def run_with_label(command: List[str], label: str) -> None:
        print(f"[mortar-cli] Running ({label}):", " ".join(command))
        subprocess.run(command, env=env, check=True)

    cold_cmd: Optional[List[str]] = None
    baseline_enabled = not args.no_baseline and not args.cold_kb
    if baseline_enabled:
        cold_cmd = list(cmd)
        if "--no-dedup" not in cold_cmd:
            cold_cmd.append("--no-dedup")
        if "--cold-kb" not in cold_cmd:
            cold_cmd.append("--cold-kb")

    if args.dry_run:
        if cold_cmd:
            print("[mortar-cli] Cold baseline command:", " ".join(cold_cmd))
            print("[mortar-cli] Warm command:", " ".join(cmd))
        else:
            print("Command:", " ".join(cmd))
        print("Env overrides:", env_overrides())
        return

    if cold_cmd:
        run_with_label(cold_cmd, f"{args.profile} profile / cold baseline")
        print("[mortar-cli] Cold baseline complete; launching standard run...")
        run_with_label(cmd, f"{args.profile} profile / standard")
    else:
        run_with_label(cmd, f"{args.profile} profile")


if __name__ == "__main__":
    main()
