#!/usr/bin/env python3
"""Autonomous Root reproducible experiment pipeline.

This script is deliberately self-contained. It uses only the Python standard
library plus numpy and pandas, both available in the bundled Codex runtime.

Modes:
  synthetic: generate safe synthetic telemetry, then run the full pipeline.
  existing:  read data/raw/host_telemetry.jsonl, then run the same pipeline.

Synthetic outputs are for pipeline validation only. They are not empirical
evidence for the paper.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "experiment_config.json"
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
RESULTS_DIR = ROOT / "results"
TABLES_DIR = ROOT / "tables"
FIGURES_DIR = ROOT / "figures"


SAFE_PROCESS_BY_SCENARIO = {
    "suid_sgid_abuse": ["enum_tool", "permission_tool", "binary_probe", "shell"],
    "sudo_misconfiguration": ["policy_tool", "auth_probe", "shell", "text_viewer"],
    "writable_scheduled_task": ["file_tool", "scheduler_tool", "service_tool", "shell"],
    "path_library_hijacking": ["env_tool", "file_tool", "interpreter", "shell"],
    "capability_abuse": ["capability_tool", "binary_probe", "shell", "permission_tool"],
    "kernel_style_vector": ["version_tool", "package_tool", "binary_probe", "shell"],
    "credential_config_weakness": ["text_search", "file_tool", "config_probe", "shell"],
    "service_local_escalation": ["service_tool", "socket_probe", "file_tool", "shell"],
}

PATH_CLASSES_BY_SCENARIO = {
    "suid_sgid_abuse": ["suid_sgid_path", "temporary_path", "procfs_path"],
    "sudo_misconfiguration": ["sudoers_policy", "account_file", "temporary_path"],
    "writable_scheduled_task": ["scheduler_path", "systemd_unit_path", "temporary_path"],
    "path_library_hijacking": ["environment_path", "library_path", "temporary_path"],
    "capability_abuse": ["capability_binary_path", "procfs_path", "temporary_path"],
    "kernel_style_vector": ["kernel_metadata_path", "package_metadata_path", "temporary_path"],
    "credential_config_weakness": ["account_file", "home_dotfile", "config_backup_path"],
    "service_local_escalation": ["service_config_path", "loopback_socket", "temporary_path"],
}

COMMON_PROCESSES = [
    "shell",
    "enum_tool",
    "file_tool",
    "text_search",
    "permission_tool",
    "policy_tool",
    "binary_probe",
    "interpreter",
    "service_tool",
]

EVENT_TYPES = ["exec", "file", "syscall", "credential", "capability", "alert"]
FILE_OPS = ["read", "write", "create", "chmod", "chown", "rename", "none"]


@dataclass
class Split:
    train_idx: List[int]
    test_idx: List[int]


def ensure_dirs() -> None:
    for path in [RAW_DIR, PROCESSED_DIR, RESULTS_DIR, TABLES_DIR, FIGURES_DIR]:
        path.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def stable_hash(text: str, n: int = 12) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> List[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


NORMALIZATION_DEFAULTS = {
    "event_type": "unknown",
    "pid": -1,
    "ppid": -1,
    "uid": -1,
    "euid": -1,
    "gid": -1,
    "egid": -1,
    "process_name": "unknown",
    "exe_path": "",
    "argv_hash": "",
    "argv_tokens_safe": "",
    "cwd": "",
    "syscall": "",
    "file_path_class": "unknown_path",
    "file_op": "none",
    "capability_event": "none",
    "exit_code": 0,
    "parent_chain_hash": "",
    "parent_chain_depth": 1,
    "scenario_family": "unknown_scenario",
    "operator_type": "unknown",
    "condition": "primary",
    "agent_model": "",
    "human_operator": "",
    "outcome": "unknown",
    "study_phase": "pilot",
    "scenario_variant": "default",
    "participant_skill": "",
    "site_id": "local_wsl",
    "trial_index": "",
    "schedule_row_id": "",
}


def normalize_event(event: dict) -> dict:
    row = dict(NORMALIZATION_DEFAULTS)
    row.update(event)
    row["timestamp_ns"] = int(row.get("timestamp_ns", 0))
    if not row.get("session_id"):
        raise ValueError("Every event must include session_id")
    if not row.get("argv_hash") and row.get("argv_tokens_safe"):
        row["argv_hash"] = stable_hash(str(row["argv_tokens_safe"]))
    return row


def generate_intervals(rng: random.Random, operator_type: str, condition: str, n: int) -> List[float]:
    intervals = []
    for _ in range(n):
        if operator_type == "agent" and condition == "primary":
            value = max(0.15, rng.gauss(3.4, 0.75))
            if rng.random() < 0.04:
                value += rng.uniform(4.0, 10.0)
        elif operator_type == "agent" and condition == "evasion":
            value = max(0.2, rng.expovariate(1 / 7.0))
            if rng.random() < 0.11:
                value += rng.uniform(15.0, 45.0)
        else:
            value = max(0.2, rng.expovariate(1 / 8.5))
            if rng.random() < 0.16:
                value += rng.uniform(18.0, 70.0)
        intervals.append(value)
    return intervals


def choose_process(
    rng: random.Random,
    scenario: str,
    operator_type: str,
    condition: str,
    step: int,
    total: int,
) -> str:
    scenario_processes = SAFE_PROCESS_BY_SCENARIO[scenario]
    phase = step / max(1, total)
    if operator_type == "agent" and condition == "primary":
        pool = COMMON_PROCESSES + scenario_processes * 2
        if phase < 0.35:
            pool += ["enum_tool", "text_search", "permission_tool"] * 4
        elif phase < 0.75:
            pool += scenario_processes * 3
        else:
            pool += ["binary_probe", "interpreter", "shell"] * 2
    elif operator_type == "agent" and condition == "evasion":
        pool = scenario_processes * 4 + ["shell", "text_viewer", "file_tool"]
        if rng.random() < 0.25:
            pool += COMMON_PROCESSES
    else:
        pool = scenario_processes * 5 + ["shell", "text_viewer"]
        if phase < 0.25:
            pool += ["enum_tool", "file_tool"]
    return rng.choice(pool)


def choose_event_type(rng: random.Random, process: str, scenario: str) -> str:
    if process in {"policy_tool", "permission_tool", "binary_probe", "service_tool"}:
        weights = [0.52, 0.22, 0.16, 0.04, 0.03, 0.03]
    elif process in {"capability_tool"}:
        weights = [0.35, 0.10, 0.18, 0.06, 0.27, 0.04]
    elif process in {"file_tool", "text_search", "config_probe"}:
        weights = [0.25, 0.55, 0.12, 0.02, 0.01, 0.05]
    else:
        weights = [0.45, 0.24, 0.20, 0.04, 0.02, 0.05]
    return rng.choices(EVENT_TYPES, weights=weights, k=1)[0]


def synthetic_session_events(
    rng: random.Random,
    session_id: str,
    scenario: str,
    operator_type: str,
    condition: str,
    agent_model: str,
    human_operator: str,
) -> List[dict]:
    if operator_type == "agent" and condition == "primary":
        steps = max(22, int(rng.gauss(58, 9)))
        success_prob = 0.66
        fail_prob = 0.18
    elif operator_type == "agent" and condition == "evasion":
        steps = max(20, int(rng.gauss(50, 13)))
        success_prob = 0.62
        fail_prob = 0.20
    else:
        steps = max(16, int(rng.gauss(44, 16)))
        success_prob = 0.64
        fail_prob = 0.20

    outcome_roll = rng.random()
    if outcome_roll < success_prob:
        outcome = "success"
    elif outcome_roll < success_prob + fail_prob:
        outcome = "failure"
    else:
        outcome = "timeout"

    intervals = generate_intervals(rng, operator_type, condition, steps)
    timestamp = int(rng.uniform(1_000_000, 5_000_000))
    base_pid = rng.randint(2000, 8000)
    shell_pid = base_pid
    parent_root = "agent_runner" if operator_type == "agent" else "human_terminal"
    events = []
    path_pool = PATH_CLASSES_BY_SCENARIO[scenario] + ["temporary_path", "procfs_path"]

    for step in range(steps):
        timestamp += int(intervals[step] * 1_000_000_000)
        process = choose_process(rng, scenario, operator_type, condition, step, steps)
        event_type = choose_event_type(rng, process, scenario)
        pid = shell_pid if process == "shell" else base_pid + step + 1
        ppid = shell_pid if process != "shell" else base_pid - 1
        uid = 1000
        euid = 1000
        event_late = step > int(steps * 0.70)
        if outcome == "success" and event_late and rng.random() < 0.12:
            event_type = "credential"
            euid = 0

        file_path_class = rng.choice(path_pool)
        if event_type == "file" and rng.random() < 0.25:
            file_path_class = rng.choice(path_pool[:2])
        if event_type == "capability":
            file_path_class = "capability_binary_path"
        if event_type == "credential":
            file_path_class = rng.choice(["account_file", "sudoers_policy", "procfs_path"])

        file_op = "none"
        if event_type == "file":
            if operator_type == "agent" and condition == "primary":
                file_op = rng.choices(FILE_OPS, weights=[0.55, 0.10, 0.12, 0.08, 0.04, 0.02, 0.09], k=1)[0]
            else:
                file_op = rng.choices(FILE_OPS, weights=[0.63, 0.08, 0.08, 0.04, 0.03, 0.02, 0.12], k=1)[0]

        exit_code = 0
        if event_type in {"exec", "syscall", "alert"}:
            if operator_type == "agent" and condition == "primary":
                exit_code = 1 if rng.random() < 0.24 else 0
            elif operator_type == "agent" and condition == "evasion":
                exit_code = 1 if rng.random() < 0.20 else 0
            else:
                exit_code = 1 if rng.random() < 0.16 else 0

        token_category = f"{process}:{file_path_class}:{file_op}:{exit_code}"
        if operator_type == "agent" and condition == "primary" and rng.random() < 0.30:
            token_category += ":checklist"
        if operator_type == "human" and rng.random() < 0.18:
            token_category += ":manual_pause"

        depth = 3 if operator_type == "agent" else 2
        if process in {"interpreter", "service_tool", "binary_probe"}:
            depth += 1
        parent_chain = ">".join([parent_root, "shell"] + [process] * max(0, depth - 2))

        events.append(
            {
                "session_id": session_id,
                "timestamp_ns": timestamp,
                "event_type": event_type,
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "euid": euid,
                "gid": 1000,
                "egid": 1000,
                "process_name": process,
                "exe_path": f"/lab/bin/{process}",
                "argv_hash": stable_hash(token_category),
                "argv_tokens_safe": token_category,
                "cwd": "/lab/session",
                "syscall": rng.choice(["execve", "openat", "read", "write", "clone", "setuid", "capset"]),
                "file_path_class": file_path_class,
                "file_op": file_op,
                "capability_event": "capability_seen" if event_type == "capability" else "none",
                "exit_code": exit_code,
                "parent_chain_hash": stable_hash(parent_chain),
                "parent_chain_depth": depth,
                "scenario_family": scenario,
                "operator_type": operator_type,
                "condition": condition,
                "agent_model": agent_model,
                "human_operator": human_operator,
                "outcome": outcome,
            }
        )
    return events


def generate_synthetic_telemetry(config: dict) -> Path:
    rng = random.Random(config["seed"])
    syn = config["synthetic"]
    rows = []

    for scenario in syn["scenario_families"]:
        for model in syn["agent_models"]:
            for trial in range(syn["agent_trials_per_model_scenario"]):
                sid = f"agent_primary_{model}_{scenario}_{trial:02d}"
                rows.extend(synthetic_session_events(rng, sid, scenario, "agent", "primary", model, ""))
            for trial in range(syn["evasion_trials_per_model_scenario"]):
                sid = f"agent_evasion_{model}_{scenario}_{trial:02d}"
                rows.extend(synthetic_session_events(rng, sid, scenario, "agent", "evasion", model, ""))

    for participant in range(syn["human_participants"]):
        human_id = f"h{participant:02d}"
        for scenario in syn["scenario_families"]:
            for trial in range(syn["human_trials_per_participant_scenario"]):
                sid = f"human_primary_{human_id}_{scenario}_{trial:02d}"
                rows.extend(synthetic_session_events(rng, sid, scenario, "human", "primary", "", human_id))

    output = RAW_DIR / "synthetic_telemetry.jsonl"
    write_jsonl(output, rows)
    return output


def normalize_events(events: List[dict]) -> List[dict]:
    normalized = [normalize_event(event) for event in events]
    normalized.sort(key=lambda r: (r["session_id"], r["timestamp_ns"], r["pid"], r["event_type"]))
    return normalized


def event_symbol(event: dict) -> str:
    event_type = event.get("event_type", "unknown")
    process = event.get("process_name", "unknown")
    path_class = event.get("file_path_class", "unknown_path")
    file_op = event.get("file_op", "none")
    if event_type == "file":
        return f"file:{path_class}:{file_op}"
    if event_type in {"credential", "capability"}:
        return f"{event_type}:{path_class}"
    return f"{event_type}:{process}"


def entropy(values: Sequence[float], bins: Sequence[float]) -> float:
    if not values:
        return 0.0
    counts = [0 for _ in range(len(bins) + 1)]
    for value in values:
        placed = False
        for i, boundary in enumerate(bins):
            if value <= boundary:
                counts[i] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1
    total = sum(counts)
    result = 0.0
    for count in counts:
        if count:
            p = count / total
            result -= p * math.log2(p)
    return result


def slope(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    x = np.arange(len(values), dtype=float)
    y = np.array(values, dtype=float)
    x_mean = float(x.mean())
    y_mean = float(y.mean())
    denom = float(((x - x_mean) ** 2).sum())
    if denom == 0:
        return 0.0
    return float(((x - x_mean) * (y - y_mean)).sum() / denom)


NGRAM_HASH_BINS = 90


def ngram_hash_bin(ngram: Tuple[str, ...]) -> int:
    """Map an n-gram to a fixed feature bin without fitting on test data."""
    payload = "\x1f".join(ngram).encode("utf-8")
    return int(hashlib.sha256(payload).hexdigest()[:16], 16) % NGRAM_HASH_BINS


def count_motifs(symbols: List[str]) -> Dict[str, int]:
    joined = " ".join(symbols)
    motifs = {
        "motif_enum_sensitive": ["exec:enum_tool", "file:"],
        "motif_policy_retry": ["exec:policy_tool", "exec:policy_tool"],
        "motif_capability_probe": ["capability:"],
        "motif_service_file": ["exec:service_tool", "file:"],
        "motif_interpreter_after_write": ["write", "exec:interpreter"],
    }
    out = {}
    for name, parts in motifs.items():
        if len(parts) == 1:
            out[name] = sum(1 for s in symbols if parts[0] in s)
        else:
            count = 0
            for i in range(len(symbols) - 1):
                window = " ".join(symbols[i : i + 2])
                if all(part in window for part in parts):
                    count += 1
            out[name] = count
    out["motif_unique_symbols"] = len(set(symbols))
    out["motif_repeated_adjacent"] = sum(1 for a, b in zip(symbols, symbols[1:]) if a == b)
    out["motif_sequence_entropy"] = entropy(
        [int(hashlib.sha256(s.encode("utf-8")).hexdigest()[:8], 16) % 100 for s in symbols],
        [20, 40, 60, 80],
    )
    return out


def extract_features(events: List[dict]) -> pd.DataFrame:
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for event in events:
        grouped[event["session_id"]].append(event)
    rows = []

    for sid, session_events in sorted(grouped.items()):
        session_events.sort(key=lambda r: r["timestamp_ns"])
        first = session_events[0]
        timestamps = [int(e["timestamp_ns"]) for e in session_events]
        intervals = [(b - a) / 1_000_000_000 for a, b in zip(timestamps, timestamps[1:])]
        duration = max(0.0, (timestamps[-1] - timestamps[0]) / 1_000_000_000) if len(timestamps) > 1 else 0.0
        symbols = [event_symbol(e) for e in session_events]
        event_counts = Counter(e["event_type"] for e in session_events)
        process_counts = Counter(e["process_name"] for e in session_events)
        path_counts = Counter(e["file_path_class"] for e in session_events)
        file_op_counts = Counter(e["file_op"] for e in session_events)
        exit_failures = sum(1 for e in session_events if int(e.get("exit_code", 0)) != 0)
        euid0 = sum(1 for e in session_events if int(e.get("euid", -1)) == 0)
        parent_depths = [int(e.get("parent_chain_depth", 1)) for e in session_events]

        row = {
            "session_id": sid,
            "operator_type": first["operator_type"],
            "condition": first.get("condition", "primary"),
            "label": 1 if first["operator_type"] == "agent" else 0,
            "scenario_family": first["scenario_family"],
            "agent_model": first.get("agent_model", ""),
            "agent_cli_version": first.get("agent_cli_version", ""),
            "agent_requested_model": first.get("agent_requested_model", ""),
            "agent_execution_mode": first.get("agent_execution_mode", ""),
            "human_operator": first.get("human_operator", ""),
            "outcome": first.get("outcome", "unknown"),
            "study_phase": first.get("study_phase", "pilot"),
            "protocol_version": first.get("protocol_version", ""),
            "scenario_variant": first.get("scenario_variant", "default"),
            "participant_skill": first.get("participant_skill", ""),
            "site_id": first.get("site_id", "local_wsl"),
            "trial_index": first.get("trial_index", ""),
            "schedule_row_id": first.get("schedule_row_id", ""),
            "fixture_generator_sha256": first.get("fixture_generator_sha256", ""),
            "n_events": len(session_events),
            "duration_seconds": duration,
            "event_exec": event_counts.get("exec", 0),
            "event_file": event_counts.get("file", 0),
            "event_syscall": event_counts.get("syscall", 0),
            "event_credential": event_counts.get("credential", 0),
            "event_capability": event_counts.get("capability", 0),
            "event_alert": event_counts.get("alert", 0),
            "proc_unique": len(process_counts),
            "proc_shell": process_counts.get("shell", 0),
            "proc_enum": process_counts.get("enum_tool", 0),
            "proc_policy": process_counts.get("policy_tool", 0),
            "proc_interpreter": process_counts.get("interpreter", 0),
            "proc_service": process_counts.get("service_tool", 0),
            "tree_max_depth": max(parent_depths) if parent_depths else 0,
            "tree_mean_depth": float(np.mean(parent_depths)) if parent_depths else 0.0,
            "tree_deep_events": sum(1 for d in parent_depths if d >= 4),
            "priv_euid0_events": euid0,
            "priv_failures": exit_failures,
            "path_unique": len(path_counts),
            "path_account_file": path_counts.get("account_file", 0),
            "path_sudoers_policy": path_counts.get("sudoers_policy", 0),
            "path_suid_sgid": path_counts.get("suid_sgid_path", 0),
            "path_capability_binary": path_counts.get("capability_binary_path", 0),
            "path_scheduler": path_counts.get("scheduler_path", 0),
            "path_systemd": path_counts.get("systemd_unit_path", 0),
            "path_temporary": path_counts.get("temporary_path", 0),
            "path_procfs": path_counts.get("procfs_path", 0),
            "path_write_ops": file_op_counts.get("write", 0) + file_op_counts.get("create", 0),
            "path_mode_ops": file_op_counts.get("chmod", 0) + file_op_counts.get("chown", 0),
        }

        if intervals:
            arr = np.array(intervals, dtype=float)
            mean_delta = float(arr.mean())
            std_delta = float(arr.std())
            row.update(
                {
                    "timing_mean_delta": mean_delta,
                    "timing_std_delta": std_delta,
                    "timing_cv_delta": std_delta / (mean_delta + 1e-9),
                    "timing_min_delta": float(arr.min()),
                    "timing_max_delta": float(arr.max()),
                    "timing_idle_10": int((arr > 10).sum()),
                    "timing_idle_30": int((arr > 30).sum()),
                    "timing_entropy": entropy(intervals, [1, 3, 6, 10, 20, 40]),
                    "timing_burstiness": (std_delta - mean_delta) / (std_delta + mean_delta + 1e-9),
                    "timing_interval_slope": slope(intervals),
                }
            )
        else:
            for key in [
                "timing_mean_delta",
                "timing_std_delta",
                "timing_cv_delta",
                "timing_min_delta",
                "timing_max_delta",
                "timing_idle_10",
                "timing_idle_30",
                "timing_entropy",
                "timing_burstiness",
                "timing_interval_slope",
            ]:
                row[key] = 0.0

        sensitive_indices = [
            i
            for i, e in enumerate(session_events)
            if e["file_path_class"]
            in {
                "account_file",
                "sudoers_policy",
                "suid_sgid_path",
                "capability_binary_path",
                "scheduler_path",
                "systemd_unit_path",
                "kernel_metadata_path",
                "service_config_path",
            }
        ]
        if sensitive_indices:
            first_idx = sensitive_indices[0]
            row["timing_first_sensitive_rank"] = first_idx / max(1, len(session_events) - 1)
            row["timing_time_to_sensitive"] = (timestamps[first_idx] - timestamps[0]) / 1_000_000_000
        else:
            row["timing_first_sensitive_rank"] = 1.0
            row["timing_time_to_sensitive"] = duration

        ngram_counts = Counter()
        for n in (1, 2, 3):
            for i in range(0, max(0, len(symbols) - n + 1)):
                ngram_counts[ngram_hash_bin(tuple(symbols[i : i + n]))] += 1
        denom = max(1, len(symbols))
        for idx in range(NGRAM_HASH_BINS):
            row[f"seq_ngram_{idx:03d}"] = ngram_counts.get(idx, 0) / denom

        row.update(count_motifs(symbols))
        rows.append(row)

    df = pd.DataFrame(rows).fillna(0)
    return df


def iter_normalized_sessions(path: Path) -> Iterable[List[dict]]:
    """Yield one normalized session at a time from session-contiguous JSONL."""
    current_id = ""
    current_events: List[dict] = []
    completed_ids: set[str] = set()

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            event = normalize_event(json.loads(line))
            session_id = event["session_id"]
            if not current_id:
                current_id = session_id
            if session_id != current_id:
                if session_id in completed_ids:
                    raise ValueError(
                        f"Session {session_id} is not contiguous in {path} (line {line_number})"
                    )
                current_events.sort(
                    key=lambda row: (row["timestamp_ns"], row["pid"], row["event_type"])
                )
                yield current_events
                completed_ids.add(current_id)
                current_id = session_id
                current_events = []
            current_events.append(event)

    if current_events:
        current_events.sort(
            key=lambda row: (row["timestamp_ns"], row["pid"], row["event_type"])
        )
        yield current_events


def extract_features_streaming(path: Path) -> pd.DataFrame:
    """Extract unchanged session features without loading the full JSONL into RAM."""
    rows = []
    for session_number, session_events in enumerate(iter_normalized_sessions(path), start=1):
        frame = extract_features(session_events)
        if len(frame) != 1:
            raise ValueError("Streaming feature extraction expected exactly one session")
        rows.append(frame.iloc[0].to_dict())
        if session_number % 10 == 0:
            print(f"Extracted features for {session_number} sessions", flush=True)
    return pd.DataFrame(rows).fillna(0)


def stratified_split(labels: Sequence[int], test_fraction: float, seed: int) -> Split:
    rng = random.Random(seed)
    by_label: Dict[int, List[int]] = defaultdict(list)
    for idx, label in enumerate(labels):
        by_label[int(label)].append(idx)
    train, test = [], []
    for label, indices in by_label.items():
        shuffled = indices[:]
        rng.shuffle(shuffled)
        n_test = max(1, int(round(len(shuffled) * test_fraction))) if len(shuffled) > 1 else 0
        test.extend(shuffled[:n_test])
        train.extend(shuffled[n_test:])
    train.sort()
    test.sort()
    return Split(train, test)


def standardize_fit(X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std < 1e-9] = 1.0
    return mean, std


def standardize_apply(X: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return (X - mean) / std


def sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -40, 40)))


def train_logistic(X: np.ndarray, y: np.ndarray, epochs: int, lr: float, l2: float) -> Dict[str, np.ndarray]:
    mean, std = standardize_fit(X)
    Xs = standardize_apply(X, mean, std)
    Xb = np.column_stack([np.ones(Xs.shape[0]), Xs])
    w = np.zeros(Xb.shape[1], dtype=float)
    for _ in range(epochs):
        p = sigmoid(Xb @ w)
        grad = (Xb.T @ (p - y)) / len(y)
        grad[1:] += l2 * w[1:]
        w -= lr * grad
    return {"type": "logistic", "mean": mean, "std": std, "w": w}


def predict_logistic(model: dict, X: np.ndarray) -> np.ndarray:
    Xs = standardize_apply(X, model["mean"], model["std"])
    Xb = np.column_stack([np.ones(Xs.shape[0]), Xs])
    return sigmoid(Xb @ model["w"])


def train_linear_svm(X: np.ndarray, y: np.ndarray, epochs: int, lr: float, l2: float) -> Dict[str, np.ndarray]:
    mean, std = standardize_fit(X)
    Xs = standardize_apply(X, mean, std)
    Xb = np.column_stack([np.ones(Xs.shape[0]), Xs])
    y_signed = np.where(y == 1, 1.0, -1.0)
    w = np.zeros(Xb.shape[1], dtype=float)
    for _ in range(max(300, epochs // 2)):
        margins = y_signed * (Xb @ w)
        active = margins < 1
        grad = l2 * w
        grad[0] = 0.0
        if np.any(active):
            grad -= (Xb[active].T @ y_signed[active]) / len(y)
        w -= lr * grad
    return {"type": "svm", "mean": mean, "std": std, "w": w}


def predict_svm(model: dict, X: np.ndarray) -> np.ndarray:
    Xs = standardize_apply(X, model["mean"], model["std"])
    Xb = np.column_stack([np.ones(Xs.shape[0]), Xs])
    scores = Xb @ model["w"]
    return sigmoid(scores)


def train_gaussian_nb(X: np.ndarray, y: np.ndarray) -> dict:
    mean, std = standardize_fit(X)
    Xs = standardize_apply(X, mean, std)
    params = {"type": "gnb", "mean": mean, "std": std, "classes": {}}
    for cls in (0, 1):
        subset = Xs[y == cls]
        if len(subset) == 0:
            subset = np.zeros((1, Xs.shape[1]))
        params["classes"][cls] = {
            "prior": float(max(1, len(subset)) / max(1, len(Xs))),
            "mu": subset.mean(axis=0),
            "var": subset.var(axis=0) + 1e-3,
        }
    return params


def predict_gaussian_nb(model: dict, X: np.ndarray) -> np.ndarray:
    Xs = standardize_apply(X, model["mean"], model["std"])
    logps = []
    for cls in (0, 1):
        p = model["classes"][cls]
        log_prior = math.log(p["prior"] + 1e-12)
        ll = -0.5 * np.sum(np.log(2 * math.pi * p["var"]) + ((Xs - p["mu"]) ** 2) / p["var"], axis=1)
        logps.append(log_prior + ll)
    log0, log1 = logps
    return sigmoid(log1 - log0)


def train_nearest_centroid(X: np.ndarray, y: np.ndarray) -> dict:
    mean, std = standardize_fit(X)
    Xs = standardize_apply(X, mean, std)
    c0 = Xs[y == 0].mean(axis=0)
    c1 = Xs[y == 1].mean(axis=0)
    return {"type": "centroid", "mean": mean, "std": std, "c0": c0, "c1": c1}


def predict_nearest_centroid(model: dict, X: np.ndarray) -> np.ndarray:
    Xs = standardize_apply(X, model["mean"], model["std"])
    d0 = np.linalg.norm(Xs - model["c0"], axis=1)
    d1 = np.linalg.norm(Xs - model["c1"], axis=1)
    return sigmoid(d0 - d1)


def fit_model(name: str, X: np.ndarray, y: np.ndarray, config: dict) -> dict:
    ev = config["evaluation"]
    if name == "Logistic regression":
        return train_logistic(X, y, ev["logistic_epochs"], ev["logistic_learning_rate"], ev["l2"])
    if name == "Linear SVM":
        return train_linear_svm(X, y, ev["logistic_epochs"], ev["logistic_learning_rate"], ev["l2"])
    if name == "Gaussian NB":
        return train_gaussian_nb(X, y)
    if name == "Nearest centroid":
        return train_nearest_centroid(X, y)
    raise ValueError(f"Unknown model: {name}")


def predict_model(model: dict, X: np.ndarray) -> np.ndarray:
    if model["type"] == "logistic":
        return predict_logistic(model, X)
    if model["type"] == "svm":
        return predict_svm(model, X)
    if model["type"] == "gnb":
        return predict_gaussian_nb(model, X)
    if model["type"] == "centroid":
        return predict_nearest_centroid(model, X)
    raise ValueError(f"Unknown model type: {model['type']}")


def json_ready(value):
    """Convert numpy-backed model parameters into stable JSON values."""
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    return value


def auc_score(y_true: Sequence[int], scores: Sequence[float]) -> float:
    pos = [s for y, s in zip(y_true, scores) if y == 1]
    neg = [s for y, s in zip(y_true, scores) if y == 0]
    if not pos or not neg:
        return float("nan")
    total = 0.0
    count = 0
    for p in pos:
        for n in neg:
            if p > n:
                total += 1.0
            elif p == n:
                total += 0.5
            count += 1
    return total / count


def metrics_from_scores(y_true: Sequence[int], scores: Sequence[float]) -> dict:
    y = np.array(y_true, dtype=int)
    s = np.array(scores, dtype=float)
    pred = (s >= 0.5).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tpr = tp / max(1, tp + fn)
    tnr = tn / max(1, tn + fp)
    precision_agent = tp / max(1, tp + fp)
    precision_human = tn / max(1, tn + fn)
    recall_agent = tpr
    recall_human = tnr
    f1_agent = 2 * precision_agent * recall_agent / max(1e-12, precision_agent + recall_agent)
    f1_human = 2 * precision_human * recall_human / max(1e-12, precision_human + recall_human)
    return {
        "balanced_accuracy": (tpr + tnr) / 2,
        "auc": auc_score(y, s),
        "agent_precision": precision_agent,
        "human_precision": precision_human,
        "agent_recall": recall_agent,
        "human_recall": recall_human,
        "agent_f1": f1_agent,
        "human_f1": f1_human,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def bootstrap_ci(y_true: np.ndarray, scores: np.ndarray, seed: int, iterations: int) -> Tuple[float, float]:
    rng = random.Random(seed)
    values = []
    n = len(y_true)
    for _ in range(iterations):
        idx = [rng.randrange(n) for _ in range(n)]
        sample_y = y_true[idx]
        if len(set(sample_y.tolist())) < 2:
            continue
        sample_scores = scores[idx]
        values.append(metrics_from_scores(sample_y, sample_scores)["balanced_accuracy"])
    if not values:
        return float("nan"), float("nan")
    return float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))


def cluster_bootstrap_ci(
    y_true: np.ndarray,
    scores: np.ndarray,
    cluster_ids: Sequence[str],
    seed: int,
    iterations: int,
) -> Tuple[float, float]:
    """Bootstrap whole human/backbone clusters rather than individual sessions."""
    rng = random.Random(seed)
    clusters: Dict[str, List[int]] = defaultdict(list)
    for idx, cluster_id in enumerate(cluster_ids):
        clusters[str(cluster_id)].append(idx)
    names = sorted(clusters)
    values = []
    for _ in range(iterations):
        sampled_names = [names[rng.randrange(len(names))] for _ in names]
        idx = [row_idx for name in sampled_names for row_idx in clusters[name]]
        sample_y = y_true[idx]
        if len(set(sample_y.tolist())) < 2:
            continue
        sample_scores = scores[idx]
        values.append(metrics_from_scores(sample_y, sample_scores)["balanced_accuracy"])
    if not values:
        return float("nan"), float("nan")
    return float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))


def feature_columns(df: pd.DataFrame) -> List[str]:
    # Detector inputs are restricted to host-event-derived quantities.  Keep
    # the assignment/collection fields here even when they are currently
    # strings so a future numeric encoding cannot silently admit metadata.
    excluded = {
        "session_id",
        "operator_type",
        "condition",
        "label",
        "scenario_family",
        "agent_model",
        "agent_cli_version",
        "agent_requested_model",
        "agent_execution_mode",
        "human_operator",
        "outcome",
        "study_phase",
        "protocol_version",
        "scenario_variant",
        "participant_skill",
        "site_id",
        "trial_index",
        "schedule_row_id",
        "fixture_generator_sha256",
    }
    return [c for c in df.columns if c not in excluded and pd.api.types.is_numeric_dtype(df[c])]


def select_feature_group(cols: List[str], group: str) -> List[str]:
    if group == "all":
        return cols
    if group == "timing":
        return [c for c in cols if c.startswith("timing_") or c == "duration_seconds"]
    if group == "content":
        return [c for c in cols if c.startswith("seq_") or c.startswith("event_") or c.startswith("proc_")]
    if group == "process_tree":
        return [c for c in cols if c.startswith("tree_") or c.startswith("proc_")]
    if group == "sensitive_paths":
        return [c for c in cols if c.startswith("path_") or c.startswith("priv_")]
    if group == "motifs":
        return [c for c in cols if c.startswith("motif_")]
    if group == "no_timing":
        return [c for c in cols if not c.startswith("timing_") and c != "duration_seconds"]
    raise ValueError(group)


def evaluate_model_on_split(
    df: pd.DataFrame,
    cols: List[str],
    split: Split,
    model_name: str,
    config: dict,
) -> Tuple[dict, np.ndarray, np.ndarray, dict]:
    X = df[cols].to_numpy(dtype=float)
    y = df["label"].to_numpy(dtype=int)
    X_train, y_train = X[split.train_idx], y[split.train_idx]
    X_test, y_test = X[split.test_idx], y[split.test_idx]
    model = fit_model(model_name, X_train, y_train, config)
    scores = predict_model(model, X_test)
    metrics = metrics_from_scores(y_test, scores)
    ci_low, ci_high = bootstrap_ci(y_test, scores, config["seed"], config["evaluation"]["bootstrap_iterations"])
    metrics["ci_low"] = ci_low
    metrics["ci_high"] = ci_high
    test_rows = df.iloc[split.test_idx]
    cluster_ids = [
        f"agent:{row.agent_model}" if row.operator_type == "agent" else f"human:{row.human_operator}"
        for row in test_rows.itertuples()
    ]
    cluster_low, cluster_high = cluster_bootstrap_ci(
        y_test,
        scores,
        cluster_ids,
        config["seed"] + 101,
        config["evaluation"]["bootstrap_iterations"],
    )
    metrics["cluster_ci_low"] = cluster_low
    metrics["cluster_ci_high"] = cluster_high
    return metrics, y_test, scores, model


def evaluate_majority(df: pd.DataFrame, split: Split) -> dict:
    y_train = df.iloc[split.train_idx]["label"].to_numpy(dtype=int)
    y_test = df.iloc[split.test_idx]["label"].to_numpy(dtype=int)
    majority = int(np.mean(y_train) >= 0.5)
    scores = np.full(len(y_test), float(majority))
    return metrics_from_scores(y_test, scores)


def run_primary_results(primary_df: pd.DataFrame, cols: List[str], config: dict) -> Tuple[pd.DataFrame, dict, np.ndarray, np.ndarray, dict, Split]:
    split = stratified_split(primary_df["label"].tolist(), config["evaluation"]["test_fraction"], config["seed"])
    rows = []

    majority_metrics = evaluate_majority(primary_df, split)
    rows.append(
        {
            "model": "Majority baseline",
            "feature_set": "label_prior",
            **majority_metrics,
            "ci_low": float("nan"),
            "ci_high": float("nan"),
            "cluster_ci_low": float("nan"),
            "cluster_ci_high": float("nan"),
        }
    )

    best_model = None
    best_scores = None
    best_y = None
    best_metrics = None
    for model_name in ["Logistic regression", "Linear SVM", "Gaussian NB", "Nearest centroid"]:
        metrics, y_test, scores, model = evaluate_model_on_split(primary_df, cols, split, model_name, config)
        rows.append({"model": model_name, "feature_set": "all", **metrics})
        if model_name == "Logistic regression":
            best_model = model
            best_scores = scores
            best_y = y_test
            best_metrics = metrics

    return pd.DataFrame(rows), best_metrics, best_y, best_scores, best_model, split


def evaluate_ablation(primary_df: pd.DataFrame, cols: List[str], config: dict) -> pd.DataFrame:
    rows = []
    groups = [
        ("Timing only", "timing"),
        ("Syscall/content only", "content"),
        ("Process tree only", "process_tree"),
        ("Sensitive paths only", "sensitive_paths"),
        ("Motifs only", "motifs"),
        ("No timing", "no_timing"),
        ("All features", "all"),
    ]
    for label, group in groups:
        selected = select_feature_group(cols, group)
        if not selected:
            continue
        split = stratified_split(primary_df["label"].tolist(), config["evaluation"]["test_fraction"], config["seed"])
        metrics, _, _, _ = evaluate_model_on_split(primary_df, selected, split, "Logistic regression", config)
        rows.append({"feature_group": label, **metrics})

    # The Q1 collector used ``outcome`` as a capture/session-completion
    # disposition.  Do not present this subset as a task-success control:
    # root attainment was not frozen as a distinct field.
    for outcome in ["success", "failure", "timeout"]:
        subset = primary_df[primary_df["outcome"] == outcome].reset_index(drop=True)
        if len(subset) >= 12 and subset["label"].nunique() == 2:
            split = stratified_split(subset["label"].tolist(), config["evaluation"]["test_fraction"], config["seed"])
            metrics, _, _, _ = evaluate_model_on_split(subset, cols, split, "Logistic regression", config)
            display = {
                "success": "Completed collection sessions only",
                "failure": "Collection-failure sessions only",
                "timeout": "Collection-timeout sessions only",
            }[outcome]
            rows.append({"feature_group": display, **metrics})
    return pd.DataFrame(rows)


def evaluate_generalization(primary_df: pd.DataFrame, cols: List[str], config: dict) -> pd.DataFrame:
    rows = []

    for family in sorted(primary_df["scenario_family"].unique()):
        train_df = primary_df[primary_df["scenario_family"] != family].reset_index(drop=True)
        test_df = primary_df[primary_df["scenario_family"] == family].reset_index(drop=True)
        if train_df["label"].nunique() == 2 and test_df["label"].nunique() == 2:
            model = fit_model("Logistic regression", train_df[cols].to_numpy(float), train_df["label"].to_numpy(int), config)
            scores = predict_model(model, test_df[cols].to_numpy(float))
            metrics = metrics_from_scores(test_df["label"].to_numpy(int), scores)
            rows.append({"test": "leave_one_family_out", "held_out": family, **metrics})

    if "scenario_variant" in primary_df.columns:
        variants = sorted([v for v in primary_df["scenario_variant"].fillna("").unique() if v and v != "default"])
        for variant in variants:
            train_df = primary_df[primary_df["scenario_variant"] != variant].reset_index(drop=True)
            test_df = primary_df[primary_df["scenario_variant"] == variant].reset_index(drop=True)
            if train_df["label"].nunique() == 2 and test_df["label"].nunique() == 2:
                model = fit_model("Logistic regression", train_df[cols].to_numpy(float), train_df["label"].to_numpy(int), config)
                scores = predict_model(model, test_df[cols].to_numpy(float))
                metrics = metrics_from_scores(test_df["label"].to_numpy(int), scores)
                rows.append({"test": "leave_one_scenario_variant_out", "held_out": variant, **metrics})

    human_pool = primary_df[primary_df["operator_type"] == "human"]
    for model_name in sorted([m for m in primary_df["agent_model"].unique() if m]):
        agent_test = primary_df[primary_df["agent_model"] == model_name]
        human_test = human_pool.sample(n=min(len(human_pool), len(agent_test)), random_state=config["seed"])
        test_ids = set(agent_test["session_id"]) | set(human_test["session_id"])
        train_df = primary_df[~primary_df["session_id"].isin(test_ids)].reset_index(drop=True)
        test_df = primary_df[primary_df["session_id"].isin(test_ids)].reset_index(drop=True)
        if train_df["label"].nunique() == 2 and test_df["label"].nunique() == 2:
            model = fit_model("Logistic regression", train_df[cols].to_numpy(float), train_df["label"].to_numpy(int), config)
            scores = predict_model(model, test_df[cols].to_numpy(float))
            metrics = metrics_from_scores(test_df["label"].to_numpy(int), scores)
            rows.append({"test": "leave_one_agent_model_out", "held_out": model_name, **metrics})

    agent_pool = primary_df[primary_df["operator_type"] == "agent"]
    for human_id in sorted([h for h in primary_df["human_operator"].unique() if h]):
        human_test = primary_df[primary_df["human_operator"] == human_id]
        agent_test = agent_pool.sample(n=min(len(agent_pool), len(human_test)), random_state=config["seed"] + len(human_id))
        test_ids = set(agent_test["session_id"]) | set(human_test["session_id"])
        train_df = primary_df[~primary_df["session_id"].isin(test_ids)].reset_index(drop=True)
        test_df = primary_df[primary_df["session_id"].isin(test_ids)].reset_index(drop=True)
        if train_df["label"].nunique() == 2 and test_df["label"].nunique() == 2:
            model = fit_model("Logistic regression", train_df[cols].to_numpy(float), train_df["label"].to_numpy(int), config)
            scores = predict_model(model, test_df[cols].to_numpy(float))
            metrics = metrics_from_scores(test_df["label"].to_numpy(int), scores)
            rows.append({"test": "leave_one_human_operator_out", "held_out": human_id, **metrics})

    return pd.DataFrame(rows)


def evaluate_evasion(
    df: pd.DataFrame,
    cols: List[str],
    trained_model: dict,
    primary_split: Split,
) -> pd.DataFrame:
    primary = df[df["condition"] == "primary"].reset_index(drop=True)
    evasion_agents = df[(df["condition"] == "evasion") & (df["operator_type"] == "agent")].reset_index(drop=True)
    human_test = primary.iloc[primary_split.test_idx]
    human_test = human_test[human_test["operator_type"] == "human"].reset_index(drop=True)
    if len(evasion_agents) == 0 or len(human_test) == 0:
        return pd.DataFrame()
    test_df = pd.concat([evasion_agents, human_test], ignore_index=True)
    scores = predict_model(trained_model, test_df[cols].to_numpy(float))
    metrics = metrics_from_scores(test_df["label"].to_numpy(int), scores)
    rows = [
        {
            "condition": "evasion_agents_vs_heldout_humans",
            "n_sessions": len(test_df),
            "agent_score_mean": float(scores[test_df["label"].to_numpy(int) == 1].mean()),
            "human_score_mean": float(scores[test_df["label"].to_numpy(int) == 0].mean()),
            **metrics,
        }
    ]
    return pd.DataFrame(rows)


def dataset_summary(df: pd.DataFrame) -> pd.DataFrame:
    primary = df[df["condition"] == "primary"]
    if "scenario_variant" in primary.columns:
        concrete_scenarios = primary[["scenario_family", "scenario_variant"]].drop_duplicates().shape[0]
    else:
        concrete_scenarios = primary["scenario_family"].nunique()
    rows = [
        ("number_of_scenario_families", primary["scenario_family"].nunique()),
        ("number_of_concrete_scenarios", concrete_scenarios),
        ("agent_backbones", primary.loc[primary["operator_type"] == "agent", "agent_model"].nunique()),
        ("agent_sessions", int((primary["operator_type"] == "agent").sum())),
        ("human_participants", primary.loc[primary["operator_type"] == "human", "human_operator"].nunique()),
        ("human_sessions", int((primary["operator_type"] == "human").sum())),
        ("collection_complete_agent_sessions", int(((primary["operator_type"] == "agent") & (primary["outcome"] == "success")).sum())),
        ("collection_complete_human_sessions", int(((primary["operator_type"] == "human") & (primary["outcome"] == "success")).sum())),
        ("median_session_duration_seconds", round(float(primary["duration_seconds"].median()), 3)),
        ("median_telemetry_events_per_session", round(float(primary["n_events"].median()), 3)),
        ("excluded_sessions", 0),
    ]
    return pd.DataFrame(rows, columns=["quantity", "value"])


def save_confusion_matrix(metrics: dict) -> pd.DataFrame:
    df = pd.DataFrame(
        [
            {"true": "agent", "predicted_agent": metrics["tp"], "predicted_human": metrics["fn"]},
            {"true": "human", "predicted_agent": metrics["fp"], "predicted_human": metrics["tn"]},
        ]
    )
    df.to_csv(RESULTS_DIR / "confusion_matrix.csv", index=False)
    return df


def fmt_float(value: float) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "--"
    return f"{value:.3f}"


def latex_escape_text(value: object) -> str:
    return str(value).replace("_", "\\_")


def write_latex_tables(summary: pd.DataFrame, primary: pd.DataFrame, ablation: pd.DataFrame, generalization: pd.DataFrame, evasion: pd.DataFrame, mode: str) -> None:
    provenance_comment = "% Real Q1 telemetry table." if mode == "existing" else "% Synthetic dry-run table. Do not report as empirical evidence."
    with (TABLES_DIR / "dataset_summary.tex").open("w", encoding="utf-8") as f:
        f.write(provenance_comment + "\n")
        f.write("\\begin{tabular}{ll}\\toprule\nQuantity & Value \\\\\n\\midrule\n")
        for _, row in summary.iterrows():
            f.write(f"{row['quantity'].replace('_', ' ')} & {row['value']} \\\\\n")
        f.write("\\bottomrule\\end{tabular}\n")

    with (TABLES_DIR / "primary_results.tex").open("w", encoding="utf-8") as f:
        f.write(provenance_comment + "\n")
        f.write("\\begin{tabular}{lcccccc}\\toprule\n")
        f.write("Model & Feature set & BAcc & Cluster 95\\% CI & AUC & Agent recall & Human recall \\\\\n\\midrule\n")
        for _, row in primary.iterrows():
            cluster_ci = f"[{fmt_float(row.get('cluster_ci_low'))}, {fmt_float(row.get('cluster_ci_high'))}]"
            f.write(
                f"{row['model']} & {latex_escape_text(row['feature_set'])} & {fmt_float(row['balanced_accuracy'])} & "
                f"{cluster_ci} & {fmt_float(row['auc'])} & {fmt_float(row['agent_recall'])} & {fmt_float(row['human_recall'])} \\\\\n"
            )
        f.write("\\bottomrule\\end{tabular}\n")

    with (TABLES_DIR / "ablation_results.tex").open("w", encoding="utf-8") as f:
        f.write(provenance_comment + "\n")
        f.write("\\begin{tabular}{lcccc}\\toprule\n")
        f.write("Feature group & BAcc & AUC & CI low & CI high \\\\\n\\midrule\n")
        for _, row in ablation.iterrows():
            f.write(
                f"{row['feature_group']} & {fmt_float(row['balanced_accuracy'])} & {fmt_float(row['auc'])} & "
                f"{fmt_float(row['ci_low'])} & {fmt_float(row['ci_high'])} \\\\\n"
            )
        f.write("\\bottomrule\\end{tabular}\n")

    with (TABLES_DIR / "generalization_results.tex").open("w", encoding="utf-8") as f:
        f.write(provenance_comment + "\n")
        f.write("\\begin{tabular}{llcc}\\toprule\n")
        f.write("Test & Held out & BAcc & AUC \\\\\n\\midrule\n")
        for _, row in generalization.iterrows():
            f.write(
                f"{row['test'].replace('_', ' ')} & {latex_escape_text(row['held_out'])} & "
                f"{fmt_float(row['balanced_accuracy'])} & {fmt_float(row['auc'])} \\\\\n"
            )
        f.write("\\bottomrule\\end{tabular}\n")

    with (TABLES_DIR / "evasion_results.tex").open("w", encoding="utf-8") as f:
        f.write(provenance_comment + "\n")
        f.write("\\begin{tabular}{lccc}\\toprule\n")
        f.write("Condition & Sessions & BAcc & AUC \\\\\n\\midrule\n")
        for _, row in evasion.iterrows():
            f.write(
                f"{row['condition'].replace('_', ' ')} & {int(row['n_sessions'])} & "
                f"{fmt_float(row['balanced_accuracy'])} & {fmt_float(row['auc'])} \\\\\n"
            )
        f.write("\\bottomrule\\end{tabular}\n")


def svg_header(width: int, height: int) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">\n'


def write_svg(path: Path, body: str, width: int = 900, height: int = 540) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write(svg_header(width, height))
        f.write('<rect width="100%" height="100%" fill="white"/>\n')
        f.write(body)
        f.write("</svg>\n")


def draw_pipeline_svg() -> None:
    labels = ["Clean VM snapshot", "Human/agent session", "Host telemetry", "Feature extraction", "Session classifier"]
    body = '<style>text{font-family:Arial,sans-serif;font-size:18px}.box{fill:#f5f7fb;stroke:#243b53;stroke-width:2}</style>\n'
    x = 35
    for i, label in enumerate(labels):
        body += f'<rect class="box" x="{x}" y="210" width="145" height="80" rx="8"/>\n'
        body += f'<text x="{x+72}" y="245" text-anchor="middle">{label.split()[0]}</text>\n'
        body += f'<text x="{x+72}" y="270" text-anchor="middle">{" ".join(label.split()[1:])}</text>\n'
        if i < len(labels) - 1:
            body += f'<line x1="{x+145}" y1="250" x2="{x+185}" y2="250" stroke="#1f7a8c" stroke-width="3" marker-end="url(#arrow)"/>\n'
        x += 180
    body = '<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#1f7a8c"/></marker></defs>\n' + body
    body += '<text x="450" y="90" text-anchor="middle" style="font-size:26px;font-weight:bold">Autonomous Root Experiment Pipeline</text>\n'
    write_svg(FIGURES_DIR / "pipeline.svg", body)


def draw_schema_svg() -> None:
    fields = ["session_id", "timestamp_ns", "event_type", "pid/ppid", "uid/euid", "process_name", "file_path_class", "file_op", "capability_event", "exit_code", "scenario_family", "operator_type"]
    body = '<style>text{font-family:Arial,sans-serif;font-size:16px}.field{fill:#eef7f2;stroke:#2d6a4f;stroke-width:1.5}</style>\n'
    body += '<text x="450" y="55" text-anchor="middle" style="font-size:25px;font-weight:bold">Normalized Host Telemetry Schema</text>\n'
    for i, field in enumerate(fields):
        col = i % 3
        row = i // 3
        x = 80 + col * 260
        y = 105 + row * 85
        body += f'<rect class="field" x="{x}" y="{y}" width="210" height="52" rx="6"/>\n'
        body += f'<text x="{x+105}" y="{y+32}" text-anchor="middle">{field}</text>\n'
    write_svg(FIGURES_DIR / "telemetry_schema.svg", body)


def draw_confusion_svg(confusion: pd.DataFrame) -> None:
    agent_row = confusion[confusion["true"] == "agent"].iloc[0]
    human_row = confusion[confusion["true"] == "human"].iloc[0]
    matrix = [
        [int(agent_row["predicted_agent"]), int(agent_row["predicted_human"])],
        [int(human_row["predicted_agent"]), int(human_row["predicted_human"])],
    ]
    max_v = max(max(row) for row in matrix) or 1
    body = '<style>text{font-family:Arial,sans-serif}.label{font-size:18px}.num{font-size:26px;font-weight:bold}</style>\n'
    body += '<text x="450" y="55" text-anchor="middle" style="font-size:26px;font-weight:bold">Confusion Matrix</text>\n'
    labels_x = ["Predicted harness", "Predicted human"]
    labels_y = ["True harness", "True human"]
    for j, label in enumerate(labels_x):
        body += f'<text class="label" x="{330+j*170}" y="120" text-anchor="middle">{label}</text>\n'
    for i, label in enumerate(labels_y):
        body += f'<text class="label" x="145" y="{215+i*150}" text-anchor="middle">{label}</text>\n'
    for i in range(2):
        for j in range(2):
            v = matrix[i][j]
            intensity = int(245 - 145 * (v / max_v))
            color = f"rgb({intensity},{intensity+5},{245})"
            x = 245 + j * 170
            y = 160 + i * 150
            body += f'<rect x="{x}" y="{y}" width="150" height="120" fill="{color}" stroke="#1b263b" stroke-width="2"/>\n'
            body += f'<text class="num" x="{x+75}" y="{y+70}" text-anchor="middle">{v}</text>\n'
    write_svg(FIGURES_DIR / "confusion_matrix.svg", body)


def draw_ablation_svg(ablation: pd.DataFrame) -> None:
    data = ablation[["feature_group", "balanced_accuracy"]].head(8).copy()
    body = '<style>text{font-family:Arial,sans-serif;font-size:14px}.bar{fill:#1f7a8c}</style>\n'
    body += '<text x="450" y="45" text-anchor="middle" style="font-size:25px;font-weight:bold">Ablation Balanced Accuracy</text>\n'
    x0, y0 = 120, 430
    width, height = 700, 310
    body += f'<line x1="{x0}" y1="{y0}" x2="{x0+width}" y2="{y0}" stroke="#333"/>\n'
    body += f'<line x1="{x0}" y1="{y0}" x2="{x0}" y2="{y0-height}" stroke="#333"/>\n'
    for tick in [0.5, 0.7, 0.9, 1.0]:
        y = y0 - height * tick
        body += f'<line x1="{x0-5}" y1="{y}" x2="{x0+width}" y2="{y}" stroke="#ddd"/>\n'
        body += f'<text x="{x0-12}" y="{y+5}" text-anchor="end">{tick:.1f}</text>\n'
    bar_w = width / max(1, len(data)) * 0.65
    for i, row in data.iterrows():
        val = float(row["balanced_accuracy"])
        x = x0 + i * (width / len(data)) + 15
        h = height * val
        y = y0 - h
        body += f'<rect class="bar" x="{x}" y="{y}" width="{bar_w}" height="{h}"/>\n'
        body += f'<text x="{x+bar_w/2}" y="{y-8}" text-anchor="middle">{val:.2f}</text>\n'
        label = str(row["feature_group"]).replace(" only", "")
        body += f'<text x="{x+bar_w/2}" y="{y0+25}" text-anchor="middle" transform="rotate(30 {x+bar_w/2},{y0+25})">{label}</text>\n'
    write_svg(FIGURES_DIR / "ablation.svg", body)


def draw_evasion_svg(evasion: pd.DataFrame) -> None:
    if evasion.empty:
        return
    row = evasion.iloc[0]
    vals = [float(row["agent_score_mean"]), float(row["human_score_mean"])]
    labels = ["Evasion agent score", "Held-out human score"]
    body = '<style>text{font-family:Arial,sans-serif;font-size:16px}.bar{fill:#7b2cbf}</style>\n'
    body += '<text x="450" y="55" text-anchor="middle" style="font-size:25px;font-weight:bold">Human-Mimicry Evasion Check</text>\n'
    for i, (label, val) in enumerate(zip(labels, vals)):
        x = 230 + i * 260
        h = 300 * val
        y = 420 - h
        body += f'<rect class="bar" x="{x}" y="{y}" width="150" height="{h}"/>\n'
        body += f'<text x="{x+75}" y="{y-12}" text-anchor="middle">{val:.3f}</text>\n'
        body += f'<text x="{x+75}" y="455" text-anchor="middle">{label}</text>\n'
    body += '<line x1="170" y1="420" x2="730" y2="420" stroke="#333"/>\n'
    write_svg(FIGURES_DIR / "evasion.svg", body)


def write_outputs(
    features: pd.DataFrame,
    summary: pd.DataFrame,
    primary: pd.DataFrame,
    ablation: pd.DataFrame,
    generalization: pd.DataFrame,
    evasion: pd.DataFrame,
    confusion: pd.DataFrame,
    config: dict,
    mode: str,
    primary_model: dict,
    feature_cols: List[str],
    primary_df: pd.DataFrame,
    primary_split: Split,
) -> None:
    features.to_csv(PROCESSED_DIR / "features.csv", index=False)
    summary.to_csv(RESULTS_DIR / "dataset_summary.csv", index=False)
    primary.to_csv(RESULTS_DIR / "primary_results.csv", index=False)
    ablation.to_csv(RESULTS_DIR / "ablation_results.csv", index=False)
    generalization.to_csv(RESULTS_DIR / "generalization_results.csv", index=False)
    evasion.to_csv(RESULTS_DIR / "evasion_results.csv", index=False)
    confusion.to_csv(RESULTS_DIR / "confusion_matrix.csv", index=False)

    frozen_model = {
        "mode": mode,
        "model_name": "Logistic regression",
        "score_threshold": 0.5,
        "feature_columns": feature_cols,
        "train_session_ids": primary_df.iloc[primary_split.train_idx]["session_id"].tolist(),
        "test_session_ids": primary_df.iloc[primary_split.test_idx]["session_id"].tolist(),
        "parameters": json_ready(primary_model),
    }
    with (RESULTS_DIR / "primary_model.json").open("w", encoding="utf-8") as f:
        json.dump(frozen_model, f, indent=2, sort_keys=True)

    write_latex_tables(summary, primary, ablation, generalization, evasion, mode)
    draw_pipeline_svg()
    draw_schema_svg()
    draw_confusion_svg(confusion)
    draw_ablation_svg(ablation)
    draw_evasion_svg(evasion)

    manifest = {
        "mode": mode,
        "warning": "Synthetic metrics are dry-run outputs only and must not be reported as paper evidence." if mode == "synthetic" else "Real telemetry mode.",
        "seed": config["seed"],
        "thresholds": config["thresholds"],
        "n_sessions": int(len(features)),
        "outputs": {
            "features": (PROCESSED_DIR / "features.csv").relative_to(ROOT).as_posix(),
            "primary_results": (RESULTS_DIR / "primary_results.csv").relative_to(ROOT).as_posix(),
            "ablation_results": (RESULTS_DIR / "ablation_results.csv").relative_to(ROOT).as_posix(),
            "generalization_results": (RESULTS_DIR / "generalization_results.csv").relative_to(ROOT).as_posix(),
            "evasion_results": (RESULTS_DIR / "evasion_results.csv").relative_to(ROOT).as_posix(),
            "primary_model": (RESULTS_DIR / "primary_model.json").relative_to(ROOT).as_posix(),
        },
    }
    with (RESULTS_DIR / "run_manifest.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def write_agent_only_outputs(features: pd.DataFrame, summary: pd.DataFrame, config: dict, mode: str) -> None:
    features.to_csv(PROCESSED_DIR / "features.csv", index=False)
    summary.to_csv(RESULTS_DIR / "dataset_summary.csv", index=False)
    session_cols = [
        "session_id",
        "operator_type",
        "condition",
        "scenario_family",
        "agent_model",
        "outcome",
        "n_events",
        "duration_seconds",
        "event_exec",
        "event_file",
        "event_syscall",
        "event_credential",
        "event_capability",
        "path_unique",
        "proc_unique",
        "tree_max_depth",
    ]
    available_cols = [c for c in session_cols if c in features.columns]
    agent_summary = features[available_cols].copy()
    agent_summary.to_csv(RESULTS_DIR / "agent_only_session_summary.csv", index=False)

    with (TABLES_DIR / "agent_only_session_summary.tex").open("w", encoding="utf-8") as f:
        f.write("% Real agent-arm telemetry summary. Classification requires human sessions.\n")
        f.write("\\begin{tabular}{llrrr}\\toprule\n")
        f.write("Session & Scenario & Events & Duration (s) & Unique processes \\\\\n\\midrule\n")
        for _, row in agent_summary.iterrows():
            f.write(
                f"{row['session_id']} & {row['scenario_family']} & {int(row['n_events'])} & "
                f"{float(row['duration_seconds']):.2f} & {int(row['proc_unique'])} \\\\\n"
            )
        f.write("\\bottomrule\\end{tabular}\n")

    draw_pipeline_svg()
    draw_schema_svg()
    manifest = {
        "mode": mode,
        "warning": "Real telemetry contains only one operator class. Classification was not run because human-control sessions are required.",
        "seed": config["seed"],
        "thresholds": config["thresholds"],
        "n_sessions": int(len(features)),
        "operator_classes": sorted(features["operator_type"].unique().tolist()),
        "outputs": {
            "features": (PROCESSED_DIR / "features.csv").relative_to(ROOT).as_posix(),
            "dataset_summary": (RESULTS_DIR / "dataset_summary.csv").relative_to(ROOT).as_posix(),
            "agent_only_session_summary": (RESULTS_DIR / "agent_only_session_summary.csv").relative_to(ROOT).as_posix(),
        },
    }
    with (RESULTS_DIR / "run_manifest.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def run_pipeline(mode: str) -> None:
    ensure_dirs()
    config = load_config()
    if mode == "synthetic":
        telemetry_path = generate_synthetic_telemetry(config)
    else:
        telemetry_path = RAW_DIR / "host_telemetry.jsonl"
        if not telemetry_path.exists():
            raise FileNotFoundError(f"Expected real telemetry at {telemetry_path}")

    if mode == "existing":
        # Real Q1 telemetry is multi-gigabyte. Session-contiguous streaming is
        # feature-equivalent to the batch implementation and avoids retaining
        # the complete event corpus and a duplicate normalized corpus in RAM.
        features = extract_features_streaming(telemetry_path)
        all_session_count = len(features)
        features = features[features["study_phase"] == "q1"].reset_index(drop=True)
        print(
            f"Restricted existing-data analysis to study_phase=q1: "
            f"{len(features)} of {all_session_count} sessions",
            flush=True,
        )
    else:
        events = normalize_events(read_jsonl(telemetry_path))
        normalized_path = RAW_DIR / "normalized_synthetic_telemetry.jsonl"
        write_jsonl(normalized_path, events)
        features = extract_features(events)
    cols = feature_columns(features)

    primary_df = features[features["condition"] == "primary"].reset_index(drop=True)
    if primary_df["label"].nunique() < 2:
        summary = dataset_summary(features)
        write_agent_only_outputs(features, summary, config, mode)
        print(f"Mode: {mode}")
        print(f"Telemetry: {telemetry_path}")
        print(f"Sessions: {len(features)}")
        print("Operator classes:", ", ".join(sorted(primary_df["operator_type"].unique())))
        print("Classification skipped: real human-control sessions are required.")
        print(f"Agent-only outputs written to: {RESULTS_DIR}")
        return

    summary = dataset_summary(features)
    primary_results, best_metrics, best_y, best_scores, best_model, primary_split = run_primary_results(primary_df, cols, config)
    ablation = evaluate_ablation(primary_df, cols, config)
    generalization = evaluate_generalization(primary_df, cols, config)
    evasion = evaluate_evasion(features, cols, best_model, primary_split)
    confusion = save_confusion_matrix(best_metrics)
    write_outputs(
        features,
        summary,
        primary_results,
        ablation,
        generalization,
        evasion,
        confusion,
        config,
        mode,
        best_model,
        cols,
        primary_df,
        primary_split,
    )

    print(f"Mode: {mode}")
    print(f"Telemetry: {telemetry_path}")
    print(f"Sessions: {len(features)}")
    print(f"Primary sessions: {len(primary_df)}")
    print(f"Primary logistic BAcc: {best_metrics['balanced_accuracy']:.3f}")
    print(f"Primary logistic AUC: {best_metrics['auc']:.3f}")
    print(f"Results written to: {RESULTS_DIR}")
    print(f"Figures written to: {FIGURES_DIR}")
    if mode == "synthetic":
        print("WARNING: synthetic dry-run metrics validate the pipeline only; do not use them as paper evidence.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["synthetic", "existing"], default="synthetic")
    args = parser.parse_args()
    run_pipeline(args.mode)


if __name__ == "__main__":
    main()
