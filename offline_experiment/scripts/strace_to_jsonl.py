#!/usr/bin/env python3
"""Convert WSL strace logs into Autonomous Root JSONL telemetry.

This converter is intentionally conservative. It maps raw file paths into
classes and stores only safe argument tokens. Use it for authorized lab traces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List


ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
TRACE_DIR = RAW_DIR / "strace"
META_DIR = RAW_DIR / "session_metadata"
OUT_PATH = RAW_DIR / "host_telemetry.jsonl"
PENDING_PATH = RAW_DIR / "host_telemetry_pending_sessions.txt"

LINE_RE = re.compile(
    r"^(?:(?P<pid_plain>\d+)\s+|\[pid\s+(?P<pid_bracket>\d+)\]\s+)?"
    r"(?P<ts>\d+\.\d+)\s+"
    r"(?P<syscall>[a-zA-Z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$"
)
PATH_RE = re.compile(r'"(/[^"]*)"')


def stable_hash(text: str, n: int = 12) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def path_class(path: str) -> str:
    if not path:
        return "unknown_path"
    fixture_prefix = "/opt/autonomous_root_lab/current"
    if path == fixture_prefix:
        path = "/"
    elif path.startswith(fixture_prefix + "/"):
        path = path[len(fixture_prefix) :]
    if path in {"/etc/passwd", "/etc/shadow", "/etc/group"}:
        return "account_file"
    if "sudoers" in path:
        return "sudoers_policy"
    if "/cron" in path or "crontab" in path:
        return "scheduler_path"
    if "/systemd/" in path:
        return "systemd_unit_path"
    if path.startswith("/tmp") or path.startswith("/var/tmp"):
        return "temporary_path"
    if path.startswith("/proc"):
        return "procfs_path"
    if path.startswith("/sys"):
        return "sysfs_path"
    if "/.ssh/" in path:
        return "ssh_key_path"
    if path.startswith("/home") and "/." in path:
        return "home_dotfile"
    if path.startswith("/lib") or path.startswith("/usr/lib"):
        return "library_path"
    if path.startswith("/usr/bin") or path.startswith("/bin") or path.startswith("/usr/sbin") or path.startswith("/sbin"):
        return "system_binary_path"
    if path.startswith("/etc"):
        return "config_path"
    if "capability_inventory" in path:
        return "capability_inventory"
    if "process_snapshot" in path or "listener_snapshot" in path:
        return "service_metadata"
    return "other_path"


def event_type(syscall: str) -> str:
    if syscall in {"execve", "execveat", "clone", "fork", "vfork"}:
        return "exec"
    if syscall in {"open", "openat", "creat", "access", "stat", "newfstatat", "chmod", "fchmod", "chown", "fchown", "rename", "unlink", "mkdir"}:
        return "file"
    if syscall in {"setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid"}:
        return "credential"
    if syscall in {"capget", "capset"}:
        return "capability"
    return "syscall"


def file_op(syscall: str, args: str) -> str:
    if syscall in {"chmod", "fchmod"}:
        return "chmod"
    if syscall in {"chown", "fchown"}:
        return "chown"
    if syscall in {"rename"}:
        return "rename"
    if syscall in {"unlink"}:
        return "unlink"
    if syscall in {"creat", "mkdir"}:
        return "create"
    if "O_WRONLY" in args or "O_RDWR" in args or "O_CREAT" in args:
        return "write"
    if syscall in {"open", "openat", "access", "stat", "newfstatat"}:
        return "read"
    return "none"


def process_name(syscall: str, paths: List[str]) -> str:
    if syscall in {"execve", "execveat"} and paths:
        return Path(paths[0]).name or "exec"
    return syscall


def load_metadata(path: Path) -> Dict[str, str]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_trace(trace_path: Path, metadata: Dict[str, str]) -> Iterable[dict]:
    with trace_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = LINE_RE.match(line)
            if not m:
                continue
            syscall = m.group("syscall")
            args = m.group("args")
            paths = PATH_RE.findall(args)
            first_path = paths[0] if paths else ""
            result = m.group("result")
            exit_code = 0 if not result.startswith("-1") else 1
            pid = int(m.group("pid_plain") or m.group("pid_bracket") or -1)
            ts_ns = int(float(m.group("ts")) * 1_000_000_000)
            safe_tokens = f"{syscall}:{path_class(first_path)}:{file_op(syscall, args)}:{exit_code}"
            yield {
                "session_id": metadata["session_id"],
                "timestamp_ns": ts_ns,
                "event_type": event_type(syscall),
                "pid": pid,
                "ppid": -1,
                "uid": -1,
                "euid": -1,
                "gid": -1,
                "egid": -1,
                "process_name": process_name(syscall, paths),
                "exe_path": first_path if syscall in {"execve", "execveat"} else "",
                "argv_hash": stable_hash(safe_tokens),
                "argv_tokens_safe": safe_tokens,
                "cwd": "",
                "syscall": syscall,
                "file_path_class": path_class(first_path),
                "file_op": file_op(syscall, args),
                "capability_event": "capability_seen" if syscall in {"capget", "capset"} else "none",
                "exit_code": exit_code,
                "parent_chain_hash": "",
                "parent_chain_depth": 1,
                "scenario_family": metadata["scenario_family"],
                "operator_type": metadata["operator_type"],
                "condition": metadata.get("condition", "primary"),
                "agent_model": metadata.get("agent_model", ""),
                "agent_cli_version": metadata.get("agent_cli_version", ""),
                "agent_requested_model": metadata.get("agent_requested_model", ""),
                "agent_execution_mode": metadata.get("agent_execution_mode", ""),
                "human_operator": metadata.get("human_operator", ""),
                "outcome": metadata.get("outcome", "unknown"),
                "study_phase": metadata.get("study_phase", "pilot"),
                "protocol_version": metadata.get("protocol_version", ""),
                "scenario_variant": metadata.get("scenario_variant", "default"),
                "participant_skill": metadata.get("participant_skill", ""),
                "site_id": metadata.get("site_id", "local_wsl"),
                "trial_index": metadata.get("trial_index", ""),
                "schedule_row_id": metadata.get("schedule_row_id", ""),
                "fixture_generator_sha256": metadata.get("fixture_generator_sha256", ""),
                "campaign_id": metadata.get("campaign_id", ""),
                "attack_pattern": metadata.get("attack_pattern", ""),
                "campaign_stage": metadata.get("campaign_stage", ""),
                "trigger_state": metadata.get("trigger_state", ""),
                "expected_protected_change": metadata.get("expected_protected_change", ""),
            }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace-dir", default=str(TRACE_DIR))
    parser.add_argument("--metadata-dir", default=str(META_DIR))
    parser.add_argument("--output", default=str(OUT_PATH))
    parser.add_argument(
        "--session-id",
        default="",
        help="Convert exactly one session instead of rebuilding every trace.",
    )
    args = parser.parse_args()

    trace_dir = Path(args.trace_dir)
    metadata_dir = Path(args.metadata_dir)
    output = Path(args.output)

    if args.session_id:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.session_id):
            parser.error("--session-id contains unsafe characters")
        trace_paths = [trace_dir / f"{args.session_id}.strace"]
        if not trace_paths[0].is_file():
            raise FileNotFoundError(f"Missing trace for session {args.session_id}: {trace_paths[0]}")
    else:
        trace_paths = sorted(trace_dir.glob("*.strace"))

    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", encoding="utf-8") as f:
        for trace_path in trace_paths:
            meta_path = metadata_dir / f"{trace_path.stem}.json"
            if not meta_path.exists():
                raise FileNotFoundError(f"Missing metadata for {trace_path.name}: {meta_path}")
            metadata = load_metadata(meta_path)
            for row in parse_trace(trace_path, metadata):
                f.write(json.dumps(row, sort_keys=True) + "\n")
                count += 1

    # A successful canonical full rebuild incorporates every deferred
    # per-session export, so its pending-session marker is no longer needed.
    if (
        not args.session_id
        and trace_dir.resolve() == TRACE_DIR.resolve()
        and metadata_dir.resolve() == META_DIR.resolve()
        and output.resolve() == OUT_PATH.resolve()
    ):
        PENDING_PATH.unlink(missing_ok=True)

    print(f"Wrote {count} events to {output}")


if __name__ == "__main__":
    main()
