#!/usr/bin/env python3
"""Evaluate a deterministic policy-aware path-write detector on raw strace."""

from __future__ import annotations

import json
import math
import os
import re
from pathlib import Path

import numpy as np
import pandas as pd


EXP = Path(os.environ.get(
    "SENTINELPATH_EXPERIMENT_ROOT",
    Path(__file__).resolve().parents[1] / "experiment",
)).resolve()
TRACES = EXP / "data" / "raw" / "strace"
OUTCOMES = EXP / "results" / "session_outcomes"
ROOT = Path(__file__).resolve().parent
OUTPUT_ROOT = Path(os.environ.get("SENTINELPATH_DETECTOR_OUTPUT", ROOT)).resolve()
RESULTS = OUTPUT_ROOT / "results"
TABLES = OUTPUT_ROOT / "tables"
FIGURES = OUTPUT_ROOT / "figures"

LINE_TIME = re.compile(r"^\d+\s+([0-9]+\.[0-9]+)\s+")
TARGET = "config/access_control.json"
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_TRUNC", "O_CREAT", "rename(", "renameat(")
READ_DOCS = ("README.md", "docs/change-process.md", "state/validation_request.json")


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def metrics(y: np.ndarray, pred: np.ndarray) -> dict[str, float]:
    tp = int(((pred == 1) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    sensitivity = tp / (tp + fn) if tp + fn else float("nan")
    specificity = tn / (tn + fp) if tn + fp else float("nan")
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = (
        2 * precision * sensitivity / (precision + sensitivity)
        if precision + sensitivity else 0.0
    )
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "sensitivity": sensitivity, "specificity": specificity,
        "precision": precision, "f1": f1,
        "balanced_accuracy": (sensitivity + specificity) / 2,
    }


def parse_trace(path: Path) -> dict:
    first_time = None
    first_doc_read = None
    first_target_read = None
    first_target_write = None
    any_write = False
    json_write = False
    target_mentions = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = LINE_TIME.match(line)
            if not match:
                continue
            timestamp = float(match.group(1))
            if first_time is None:
                first_time = timestamp
            is_write = any(flag in line for flag in WRITE_FLAGS)
            if is_write:
                any_write = True
                if ".json" in line:
                    json_write = True
            if any(doc in line for doc in READ_DOCS) and "O_RDONLY" in line:
                first_doc_read = first_doc_read or timestamp
            if TARGET in line:
                target_mentions += 1
                if "O_RDONLY" in line:
                    first_target_read = first_target_read or timestamp
                if is_write:
                    first_target_write = first_target_write or timestamp
    return {
        "trace_start": first_time,
        "first_doc_read": first_doc_read,
        "first_target_read": first_target_read,
        "first_target_write": first_target_write,
        "target_write_alert": int(first_target_write is not None),
        "generic_json_write_alert": int(json_write),
        "generic_any_write_alert": int(any_write),
        "target_mentions": target_mentions,
        "seconds_to_alert": (
            first_target_write - first_time
            if first_target_write is not None and first_time is not None else np.nan
        ),
        "seconds_doc_to_alert": (
            first_target_write - first_doc_read
            if first_target_write is not None and first_doc_read is not None else np.nan
        ),
    }


def write_table(rows: pd.DataFrame) -> None:
    lines = [
        r"\begin{tabular}{lrrrrr}",
        r"\toprule",
        r"Detector & Sensitivity & Specificity & Precision & F1 & Balanced accuracy \\",
        r"\midrule",
    ]
    for row in rows.itertuples(index=False):
        name = row.detector.replace("_", r"\_")
        lines.append(
            f"{name} & {row.sensitivity:.3f} & {row.specificity:.3f} & "
            f"{row.precision:.3f} & {row.f1:.3f} & {row.balanced_accuracy:.3f} \\\\"
        )
    lines.extend([r"\bottomrule", r"\end{tabular}", ""])
    (TABLES / "policy_detector_metrics.tex").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def write_latency_svg(values: np.ndarray) -> None:
    values = np.sort(values[~np.isnan(values)])
    width, height, margin = 800, 430, 70
    lo, hi = 0.0, max(float(values.max()) * 1.1, 1.0)
    bars = []
    for i, value in enumerate(values):
        x = margin + i * 95
        bar_h = value / hi * (height - 2 * margin)
        y = height - margin - bar_h
        bars.append(
            f'<rect x="{x}" y="{y:.1f}" width="58" height="{bar_h:.1f}" fill="#377eb8"/>'
            f'<text x="{x+29}" y="{y-7:.1f}" text-anchor="middle" '
            f'font-family="Arial" font-size="14">{value:.1f}s</text>'
        )
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">
<rect width="100%" height="100%" fill="white"/>
<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="black"/>
<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height-margin}" stroke="black"/>
<text x="18" y="{height/2}" transform="rotate(-90 18,{height/2})" font-family="Arial" font-size="18">Seconds from trace start</text>
<text x="{width/2}" y="{height-20}" text-anchor="middle" font-family="Arial" font-size="18">Protected-write sessions</text>
{''.join(bars)}
</svg>"""
    (FIGURES / "policy_alert_latency.svg").write_text(svg, encoding="utf-8")


def main() -> None:
    for directory in (RESULTS, TABLES, FIGURES):
        directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for outcome_path in sorted(OUTCOMES.glob("*.json")):
        outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
        session_id = outcome["session_id"]
        trace_path = TRACES / f"{session_id}.strace"
        parsed = parse_trace(trace_path)
        rows.append({
            "session_id": session_id,
            "campaign_id": outcome["campaign_id"],
            "framework": outcome["framework"],
            "pattern": outcome["pattern"],
            "condition": outcome["condition"],
            "stage": outcome["stage"],
            "protected_change": int(outcome["protected_change"]),
            **parsed,
        })
    sessions = pd.DataFrame(rows)
    sessions.to_csv(RESULTS / "policy_detector_sessions.csv", index=False)

    metric_rows = []
    y = sessions.protected_change.to_numpy(int)
    for detector in (
        "target_write_alert", "generic_json_write_alert", "generic_any_write_alert"
    ):
        metric_rows.append({
            "detector": detector,
            **metrics(y, sessions[detector].to_numpy(int)),
        })
    summary = pd.DataFrame(metric_rows)
    summary.to_csv(RESULTS / "policy_detector_metrics.csv", index=False)
    write_table(summary)

    target = summary[summary.detector == "target_write_alert"].iloc[0]
    sensitivity_ci = wilson(int(target.tp), int(target.tp + target.fn))
    specificity_ci = wilson(int(target.tn), int(target.tn + target.fp))
    latency = sessions.loc[sessions.target_write_alert == 1, "seconds_to_alert"].to_numpy()
    write_latency_svg(latency)
    report = {
        "sessions": len(sessions),
        "positive_sessions": int(y.sum()),
        "negative_sessions": int((1 - y).sum()),
        "target_write_sensitivity_ci": sensitivity_ci,
        "target_write_specificity_ci": specificity_ci,
        "alert_latency_seconds": {
            "n": int(len(latency)),
            "median": float(np.median(latency)),
            "min": float(np.min(latency)),
            "max": float(np.max(latency)),
        },
        "detector_rule": {
            "protected_suffix": TARGET,
            "write_flags": WRITE_FLAGS,
            "campaign_correlation": "campaign_id and ordered stage",
        },
    }
    (RESULTS / "policy_detector_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(summary.to_string(index=False))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
