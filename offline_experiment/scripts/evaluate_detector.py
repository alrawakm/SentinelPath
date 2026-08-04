#!/usr/bin/env python3
"""Campaign-held-out evaluation for the staged/trigger pilot corpus."""

from __future__ import annotations

import json
import math
import os
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parent
SOURCE = Path(os.environ.get(
    "SENTINELPATH_CAMPAIGN_FEATURES",
    ROOT.parent / "experiment" / "data" / "processed" / "cumulative_campaign_features.csv",
)).resolve()
OUTPUT_ROOT = Path(os.environ.get("SENTINELPATH_MODEL_OUTPUT", ROOT)).resolve()
OUT = OUTPUT_ROOT / "results"
TABLES = OUTPUT_ROOT / "tables"
FIGURES = OUTPUT_ROOT / "figures"
SEED = 20260730

FAMILIES = {
    "volume": [
        "log_events", "log_duration", "events_per_second",
    ],
    "process": [
        "r_event_exec", "r_proc_shell", "r_proc_interpreter",
        "r_proc_service", "r_tree_deep",
    ],
    "filesystem": [
        "r_event_file", "r_path_unique", "r_path_write",
        "r_path_mode", "r_path_temporary", "r_path_procfs",
    ],
    "privilege": [
        "r_event_credential", "r_event_capability", "r_priv_euid0",
        "r_priv_failures",
    ],
    "motif": [
        "r_motif_policy_retry", "r_motif_capability_probe",
        "r_motif_service_file", "r_motif_interpreter_after_write",
        "motif_sequence_entropy",
    ],
}


def safe_col(df: pd.DataFrame, name: str) -> np.ndarray:
    if name not in df:
        return np.zeros(len(df), dtype=float)
    return pd.to_numeric(df[name], errors="coerce").fillna(0).to_numpy(float)


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    n = np.maximum(safe_col(df, "cum_n_events"), 1.0)
    duration = np.maximum(safe_col(df, "cum_duration_seconds"), 1e-6)
    out = pd.DataFrame(index=df.index)
    out["log_events"] = np.log1p(n)
    out["log_duration"] = np.log1p(duration)
    out["events_per_second"] = np.log1p(n / duration)

    mappings = {
        "r_event_exec": "cum_event_exec",
        "r_event_file": "cum_event_file",
        "r_event_credential": "cum_event_credential",
        "r_event_capability": "cum_event_capability",
        "r_proc_shell": "cum_proc_shell",
        "r_proc_interpreter": "cum_proc_interpreter",
        "r_proc_service": "cum_proc_service",
        "r_tree_deep": "cum_tree_deep_events",
        "r_priv_euid0": "cum_priv_euid0_events",
        "r_priv_failures": "cum_priv_failures",
        "r_path_unique": "cum_path_unique",
        "r_path_write": "cum_path_write_ops",
        "r_path_mode": "cum_path_mode_ops",
        "r_path_temporary": "cum_path_temporary",
        "r_path_procfs": "cum_path_procfs",
        "r_motif_policy_retry": "cum_motif_policy_retry",
        "r_motif_capability_probe": "cum_motif_capability_probe",
        "r_motif_service_file": "cum_motif_service_file",
        "r_motif_interpreter_after_write": "cum_motif_interpreter_after_write",
    }
    for target, source in mappings.items():
        out[target] = safe_col(df, source) / n
    out["motif_sequence_entropy"] = safe_col(df, "mean_motif_sequence_entropy")
    return out


def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -35, 35)))


def fit_logistic(X: np.ndarray, y: np.ndarray, ridge: float = 1.0) -> np.ndarray:
    Xb = np.column_stack([np.ones(len(X)), X])
    w = np.zeros(Xb.shape[1])
    penalty = np.eye(Xb.shape[1]) * ridge
    penalty[0, 0] = 0.0
    for _ in range(100):
        p = sigmoid(Xb @ w)
        weights = np.maximum(p * (1 - p), 1e-6)
        h = Xb.T @ (weights[:, None] * Xb) + penalty
        g = Xb.T @ (p - y) + penalty @ w
        step = np.linalg.solve(h + np.eye(len(w)) * 1e-9, g)
        w -= step
        if np.max(np.abs(step)) < 1e-8:
            break
    return w


def predict_logistic(X: np.ndarray, w: np.ndarray) -> np.ndarray:
    return sigmoid(np.column_stack([np.ones(len(X)), X]) @ w)


def residualize(
    train_x: np.ndarray,
    test_x: np.ndarray,
    train_framework: np.ndarray,
    test_framework: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    train_z = np.zeros_like(train_x)
    test_z = np.zeros_like(test_x)
    global_mean = train_x.mean(axis=0)
    global_std = train_x.std(axis=0)
    global_std[global_std < 1e-9] = 1.0
    for fw in np.unique(np.concatenate([train_framework, test_framework])):
        mask = train_framework == fw
        if mask.sum() >= 2:
            mean = train_x[mask].mean(axis=0)
            std = train_x[mask].std(axis=0)
            std[std < 1e-9] = 1.0
        else:
            mean, std = global_mean, global_std
        train_z[mask] = (train_x[mask] - mean) / std
        test_z[test_framework == fw] = (test_x[test_framework == fw] - mean) / std
    return np.clip(train_z, -8, 8), np.clip(test_z, -8, 8)


def auc(y: np.ndarray, score: np.ndarray) -> float:
    pos = score[y == 1]
    neg = score[y == 0]
    if not len(pos) or not len(neg):
        return float("nan")
    wins = sum((p > neg).sum() + 0.5 * (p == neg).sum() for p in pos)
    return float(wins / (len(pos) * len(neg)))


def metrics(y: np.ndarray, score: np.ndarray) -> dict[str, float]:
    pred = (score >= 0.5).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tpr = tp / (tp + fn) if tp + fn else float("nan")
    tnr = tn / (tn + fp) if tn + fp else float("nan")
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0.0
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "auc": auc(y, score),
        "balanced_accuracy": (tpr + tnr) / 2,
        "sensitivity": tpr,
        "specificity": tnr,
        "precision": precision,
        "f1": f1,
        "mcc": (tp * tn - fp * fn) / denom if denom else 0.0,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    }


def loocv(
    df: pd.DataFrame,
    feature_names: list[str],
    residual: bool,
    framework_only: bool = False,
    label_col: str = "campaign_label",
) -> pd.DataFrame:
    feats = build_features(df)
    X0 = feats[feature_names].to_numpy(float)
    y = df[label_col].to_numpy(int)
    fw = df["framework"].astype(str).to_numpy()
    rows = []
    for i in range(len(df)):
        train = np.arange(len(df)) != i
        test = ~train
        if framework_only:
            levels = sorted(set(fw[train]))
            Xtr = np.column_stack([(fw[train] == level).astype(float) for level in levels])
            Xte = np.column_stack([(fw[test] == level).astype(float) for level in levels])
        elif residual:
            Xtr, Xte = residualize(X0[train], X0[test], fw[train], fw[test])
        else:
            mean = X0[train].mean(axis=0)
            std = X0[train].std(axis=0)
            std[std < 1e-9] = 1.0
            Xtr = np.clip((X0[train] - mean) / std, -8, 8)
            Xte = np.clip((X0[test] - mean) / std, -8, 8)
        w = fit_logistic(Xtr, y[train], ridge=4.0)
        score = float(predict_logistic(Xte, w)[0])
        rows.append({
            "campaign_id": df.iloc[i]["campaign_id"],
            "framework": fw[i],
            "pattern": df.iloc[i]["pattern"],
            "condition": df.iloc[i]["condition"],
            "label": int(y[i]),
            "score": score,
        })
    return pd.DataFrame(rows)


def bootstrap_ci(pred: pd.DataFrame, key: str, n_boot: int = 5000) -> tuple[float, float]:
    rng = np.random.default_rng(SEED)
    values = []
    y = pred["label"].to_numpy(int)
    s = pred["score"].to_numpy(float)
    for _ in range(n_boot):
        idx = rng.integers(0, len(pred), len(pred))
        if len(np.unique(y[idx])) < 2:
            continue
        values.append(metrics(y[idx], s[idx])[key])
    return tuple(np.quantile(values, [0.025, 0.975]))


def write_table(summary: pd.DataFrame) -> None:
    lines = [
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"Model & AUROC & Balanced accuracy & F1 & MCC \\",
        r"\midrule",
    ]
    for row in summary.itertuples(index=False):
        name = str(row.model).replace("_", r"\_")
        lines.append(
            f"{name} & {row.auc:.3f} & {row.balanced_accuracy:.3f} & "
            f"{row.f1:.3f} & {row.mcc:.3f} \\\\"
        )
    lines.extend([r"\bottomrule", r"\end{tabular}", ""])
    (TABLES / "detector_comparison.tex").write_text("\n".join(lines), encoding="utf-8")


def write_svg(pred: pd.DataFrame) -> None:
    width, height = 900, 460
    margin = 70
    rows = []
    ordered = pred.sort_values(["label", "framework", "score"]).reset_index(drop=True)
    for i, row in ordered.iterrows():
        x = margin + i * (width - 2 * margin) / max(len(ordered) - 1, 1)
        y = height - margin - row.score * (height - 2 * margin)
        color = "#d95f02" if row.label else "#1b9e77"
        shape = (
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="{color}"/>'
            if row.framework == "agent01_codex"
            else f'<rect x="{x-5:.1f}" y="{y-5:.1f}" width="10" height="10" fill="{color}"/>'
        )
        rows.append(shape)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">
<rect width="100%" height="100%" fill="white"/>
<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="black"/>
<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height-margin}" stroke="black"/>
<line x1="{margin}" y1="{height/2}" x2="{width-margin}" y2="{height/2}" stroke="#777" stroke-dasharray="5,5"/>
<text x="18" y="{height/2}" transform="rotate(-90 18,{height/2})" font-family="Arial" font-size="18">Held-out attack probability</text>
<text x="{width/2}" y="{height-18}" text-anchor="middle" font-family="Arial" font-size="18">Campaigns ordered by label, framework, and score</text>
<text x="{margin-12}" y="{height-margin+5}" text-anchor="end" font-family="Arial">0</text>
<text x="{margin-12}" y="{height/2+5}" text-anchor="end" font-family="Arial">0.5</text>
<text x="{margin-12}" y="{margin+5}" text-anchor="end" font-family="Arial">1</text>
{''.join(rows)}
<circle cx="650" cy="30" r="6" fill="#555"/><text x="665" y="35" font-family="Arial">Codex</text>
<rect x="735" y="25" width="10" height="10" fill="#555"/><text x="750" y="35" font-family="Arial">Claude</text>
<circle cx="650" cy="52" r="6" fill="#1b9e77"/><text x="665" y="57" font-family="Arial">Control</text>
<circle cx="735" cy="52" r="6" fill="#d95f02"/><text x="750" y="57" font-family="Arial">Attack</text>
</svg>"""
    (FIGURES / "heldout_scores.svg").write_text(svg, encoding="utf-8")


def main() -> None:
    for path in (OUT, TABLES, FIGURES):
        path.mkdir(parents=True, exist_ok=True)
    cumulative = pd.read_csv(SOURCE)
    endpoints = cumulative.sort_values("observed_stages").groupby(
        "campaign_id", as_index=False
    ).tail(1).reset_index(drop=True)
    all_features = [f for names in FAMILIES.values() for f in names]

    predictions = {}
    predictions["Framework-only baseline"] = loocv(
        endpoints, all_features, residual=False, framework_only=True
    )
    predictions["Raw pooled telemetry"] = loocv(
        endpoints, all_features, residual=False
    )
    predictions["Framework-residual detector"] = loocv(
        endpoints, all_features, residual=True
    )
    for family, names in FAMILIES.items():
        predictions[f"Ablation: {family} only"] = loocv(
            endpoints, names, residual=True
        )

    summary_rows = []
    for name, pred in predictions.items():
        pred.to_csv(OUT / (name.lower().replace(" ", "_").replace(":", "") + ".csv"), index=False)
        row = {"model": name, **metrics(pred.label.to_numpy(), pred.score.to_numpy())}
        if name == "Framework-residual detector":
            for key in ("auc", "balanced_accuracy", "f1", "mcc"):
                low, high = bootstrap_ci(pred, key)
                row[f"{key}_ci_low"] = low
                row[f"{key}_ci_high"] = high
        summary_rows.append(row)
    summary = pd.DataFrame(summary_rows)
    summary.to_csv(OUT / "model_comparison.csv", index=False)
    write_table(summary)
    best = predictions["Framework-residual detector"]
    write_svg(best)

    subgroup_rows = []
    for keys, group in best.groupby(["framework", "pattern"]):
        subgroup_rows.append({
            "framework": keys[0],
            "pattern": keys[1],
            **metrics(group.label.to_numpy(), group.score.to_numpy()),
            "n": len(group),
        })
    pd.DataFrame(subgroup_rows).to_csv(OUT / "subgroup_metrics.csv", index=False)

    executed = endpoints[endpoints.framework.isin([
        "agent01_codex", "agent03_cursor"
    ])].reset_index(drop=True)
    execution_models = {
        "Execution detector: all features": loocv(
            executed, all_features, residual=False, label_col="any_protected_change"
        ),
        "Execution detector: filesystem": loocv(
            executed, FAMILIES["filesystem"], residual=False,
            label_col="any_protected_change"
        ),
        "Execution detector: filesystem+privilege": loocv(
            executed, FAMILIES["filesystem"] + FAMILIES["privilege"],
            residual=False, label_col="any_protected_change"
        ),
    }
    execution_rows = []
    for name, pred in execution_models.items():
        pred.to_csv(
            OUT / (name.lower().replace(" ", "_").replace(":", "") + ".csv"),
            index=False,
        )
        row = {
            "model": name,
            **metrics(pred.label.to_numpy(), pred.score.to_numpy()),
        }
        for key in ("auc", "balanced_accuracy", "f1", "mcc"):
            low, high = bootstrap_ci(pred, key)
            row[f"{key}_ci_low"] = low
            row[f"{key}_ci_high"] = high
        execution_rows.append(row)
    execution_summary = pd.DataFrame(execution_rows)
    execution_summary.to_csv(OUT / "execution_detector_comparison.csv", index=False)

    manifest = {
        "source": str(SOURCE),
        "seed": SEED,
        "campaign_endpoints": len(endpoints),
        "positive_campaigns": int(endpoints.campaign_label.sum()),
        "negative_campaigns": int((1 - endpoints.campaign_label).sum()),
        "features": all_features,
        "validation": "leave-one-campaign-out",
        "ridge": 4.0,
        "bootstrap_replicates": 5000,
    }
    (OUT / "evaluation_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(summary[["model", "auc", "balanced_accuracy", "f1", "mcc"]].to_string(index=False))
    print("\nEXECUTION TARGET (CODEX AND CURSOR CAMPAIGNS)")
    print(execution_summary[[
        "model", "auc", "balanced_accuracy", "f1", "mcc"
    ]].to_string(index=False))


if __name__ == "__main__":
    main()
