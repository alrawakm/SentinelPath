#!/usr/bin/env python3
import argparse
import importlib.util
import json
import math
import pathlib
import subprocess
import sys

import numpy as np
import pandas as pd


ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
RESULTS = ROOT / "results"
TABLES = ROOT / "tables"


def load_module(path):
    spec = importlib.util.spec_from_file_location("feature_pipeline", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_metadata():
    rows = []
    for path in sorted((RAW / "session_metadata").glob("*.json")):
        row = json.loads(path.read_text(encoding="utf-8"))
        row["metadata_path"] = str(path)
        rows.append(row)
    return pd.DataFrame(rows)


def load_outcomes():
    rows = []
    for path in sorted((RESULTS / "session_outcomes").glob("*.json")):
        row = json.loads(path.read_text(encoding="utf-8"))
        row["outcome_path"] = str(path)
        rows.append(row)
    return pd.DataFrame(rows)


def baseline_scores(features, model_path):
    model = json.loads(model_path.read_text(encoding="utf-8"))
    cols = model["feature_columns"]
    missing = [c for c in cols if c not in features.columns]
    if missing:
        raise ValueError(f"Missing baseline feature columns: {missing}")
    X = features[cols].to_numpy(dtype=float)
    mean = np.asarray(model["parameters"]["mean"], dtype=float)
    std = np.asarray(model["parameters"]["std"], dtype=float)
    w = np.asarray(model["parameters"]["w"], dtype=float)
    Xs = (X - mean) / np.where(std == 0, 1.0, std)
    Xb = np.column_stack([np.ones(len(Xs)), Xs])
    z = np.clip(Xb @ w, -40, 40)
    return 1.0 / (1.0 + np.exp(-z))


def cumulative_rows(df, feature_cols):
    additive_prefixes = (
        "event_",
        "proc_",
        "tree_",
        "priv_",
        "path_",
        "seq_ngram_",
        "motif_",
    )
    additive = [
        c for c in feature_cols
        if c == "n_events" or c == "duration_seconds" or c.startswith(additive_prefixes)
    ]
    mean_cols = [c for c in feature_cols if c not in additive]
    rows = []
    for campaign_id, group in df.groupby("campaign_id", sort=True):
        group = group.sort_values("campaign_stage")
        for position in range(1, len(group) + 1):
            prefix = group.iloc[:position]
            row = {
                "campaign_id": campaign_id,
                "framework": prefix.iloc[0]["framework"],
                "pattern": prefix.iloc[0]["pattern"],
                "condition": prefix.iloc[0]["condition"],
                "observed_stages": position,
                "final_stage": int(prefix.iloc[-1]["campaign_stage"]),
                "campaign_label": int(
                    prefix.iloc[0]["condition"] in {"staged_attack", "trigger_satisfied"}
                ),
                "any_protected_change": int(prefix["protected_change"].astype(bool).any()),
            }
            for col in additive:
                row[f"cum_{col}"] = float(prefix[col].sum())
            for col in mean_cols:
                row[f"mean_{col}"] = float(prefix[col].mean())
            rows.append(row)
    return pd.DataFrame(rows)


def wilson(successes, total, z=1.959963984540054):
    if total == 0:
        return (math.nan, math.nan)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def execution_summary(df):
    rows = []
    keys = ["framework", "pattern", "condition", "campaign_stage"]
    for key, group in df.groupby(keys, dropna=False, sort=True):
        successes = int(group["protected_change"].astype(bool).sum())
        total = len(group)
        low, high = wilson(successes, total)
        rows.append({
            **dict(zip(keys, key)),
            "n": total,
            "protected_changes": successes,
            "rate": successes / total if total else math.nan,
            "ci_low": low,
            "ci_high": high,
        })
    return pd.DataFrame(rows)


def write_execution_table(summary):
    lines = [
        "\\begin{tabular}{llllrrrr}",
        "\\hline",
        "Framework & Pattern & Condition & Stage & $n$ & Changes & Rate & 95\\% CI \\\\",
        "\\hline",
    ]
    for row in summary.itertuples(index=False):
        framework = str(row.framework).replace("_", "\\_")
        pattern = str(row.pattern).replace("_", "\\_")
        condition = str(row.condition).replace("_", "\\_")
        ci = f"[{row.ci_low:.3f}, {row.ci_high:.3f}]"
        lines.append(
            f"{framework} & {pattern} & {condition} & {int(row.campaign_stage)} & "
            f"{int(row.n)} & {int(row.protected_changes)} & {row.rate:.3f} & {ci} \\\\"
        )
    lines.extend(["\\hline", "\\end{tabular}", ""])
    TABLES.mkdir(parents=True, exist_ok=True)
    (TABLES / "execution_rates.tex").write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline-model",
        default=str(ROOT / "config" / "baseline_primary_model.json"),
    )
    args = parser.parse_args()

    PROCESSED.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    converter = ROOT / "scripts" / "strace_to_jsonl.py"
    subprocess.run([
        sys.executable,
        str(converter),
        "--trace-dir",
        str(RAW / "strace"),
        "--metadata-dir",
        str(RAW / "session_metadata"),
        "--output",
        str(RAW / "host_telemetry.jsonl"),
    ], check=True)

    pipeline = load_module(ROOT / "scripts" / "feature_pipeline.py")
    features = pipeline.extract_features_streaming(RAW / "host_telemetry.jsonl")
    metadata = load_metadata()
    outcomes = load_outcomes()
    if features.empty:
        raise RuntimeError("No session features were extracted.")
    merged = features.merge(metadata, on="session_id", how="left", suffixes=("", "_meta"))
    merged = merged.merge(
        outcomes[[
            "session_id",
            "campaign_id",
            "framework",
            "pattern",
            "condition",
            "stage",
            "expected_change",
            "protected_change",
            "execution_match",
        ]],
        on="session_id",
        how="left",
        suffixes=("", "_outcome"),
    )
    merged["campaign_stage"] = pd.to_numeric(
        merged["campaign_stage"].replace("", np.nan).fillna(merged["stage"]),
        errors="raise",
    ).astype(int)
    merged["baseline_agent_score"] = baseline_scores(
        merged,
        pathlib.Path(args.baseline_model),
    )
    merged["baseline_agent_prediction"] = (
        merged["baseline_agent_score"] >= 0.5
    ).astype(int)
    merged.to_csv(PROCESSED / "session_features_and_scores.csv", index=False)

    model = json.loads(pathlib.Path(args.baseline_model).read_text(encoding="utf-8"))
    cumulative = cumulative_rows(merged, model["feature_columns"])
    cumulative.to_csv(PROCESSED / "cumulative_campaign_features.csv", index=False)

    summary = execution_summary(merged)
    summary.to_csv(RESULTS / "execution_rates.csv", index=False)
    write_execution_table(summary)
    print(json.dumps({
        "sessions": len(merged),
        "campaigns": int(merged["campaign_id"].nunique()),
        "execution_rate_rows": len(summary),
        "session_features": str(PROCESSED / "session_features_and_scores.csv"),
        "cumulative_features": str(PROCESSED / "cumulative_campaign_features.csv"),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
