import csv
import math
import random
import statistics
from pathlib import Path

BASE = Path(__file__).resolve().parent
INPUT = BASE / "trial_metrics.csv"
OUTPUT = BASE / "trial_summary.csv"
BOOTSTRAP = 10000
SEED = 20260730

rows = list(csv.DictReader(INPUT.open(newline="", encoding="utf-8")))
groups = {}
for row in rows:
    groups.setdefault(row["condition"], []).append(float(row["ns_per_operation"]))

def percentile(values, probability):
    ordered = sorted(values)
    position = probability * (len(ordered) - 1)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight

def bootstrap_mean_ci(values):
    generator = random.Random(SEED)
    estimates = []
    count = len(values)
    for _ in range(BOOTSTRAP):
        estimates.append(statistics.mean(generator.choice(values) for _ in range(count)))
    return percentile(estimates, 0.025), percentile(estimates, 0.975)

summary = []
for condition, values in sorted(groups.items()):
    low, high = bootstrap_mean_ci(values)
    summary.append({
        "condition": condition,
        "trials": len(values),
        "mean_ns": statistics.mean(values),
        "sd_ns": statistics.stdev(values),
        "median_ns": statistics.median(values),
        "bootstrap_mean_ci_low_ns": low,
        "bootstrap_mean_ci_high_ns": high,
    })

comparisons = [
    ("monitored_unrelated_write", "baseline_write"),
    ("protected_read", "baseline_read"),
    ("protected_authorized_write", "baseline_write"),
    ("protected_unauthorized_write", "baseline_write"),
]
comparison_rows = []
for treatment, baseline in comparisons:
    treatment_values = groups[treatment]
    baseline_values = groups[baseline]
    ratios = [
        100.0 * (treated / base - 1.0)
        for treated, base in zip(treatment_values, baseline_values)
    ]
    low, high = bootstrap_mean_ci(ratios)
    comparison_rows.append({
        "comparison": f"{treatment}_vs_{baseline}",
        "mean_overhead_percent": statistics.mean(ratios),
        "median_overhead_percent": statistics.median(ratios),
        "bootstrap_mean_ci_low_percent": low,
        "bootstrap_mean_ci_high_percent": high,
    })

with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=summary[0].keys())
    writer.writeheader()
    writer.writerows(summary)

comparison_output = BASE / "trial_comparisons.csv"
with comparison_output.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=comparison_rows[0].keys())
    writer.writeheader()
    writer.writerows(comparison_rows)

print(OUTPUT.read_text(encoding="utf-8"), end="")
print(comparison_output.read_text(encoding="utf-8"), end="")
