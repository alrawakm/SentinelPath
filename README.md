# SentinelPath reproducibility package

This repository contains the source, raw observations, analysis scripts, and
paper files for the SentinelPath BPF-LSM enforcement experiment.

## Reported online experiment

- Linux `6.18.33.2-microsoft-standard-WSL2`
- ext4 filesystem
- Clang 14.0.0 and GCC 11.4.0
- libbpf commit `f7081a6baf3f54949aacb8c2fc11bb30783b83e9`
- 100 attempts in each of eight bypass or utility cells
- 30 independent timing trials per benchmark condition
- 100,000 operations per timing trial

The raw results are committed under `results/`. The event log contains 90,000
online decisions. No result is simulated or reconstructed from a manuscript
table.

## Layout

- `bpf/`: BPF program, userspace loader and launcher, benchmarks, trial scripts,
  and analysis
- `results/`: raw and summarized CSV data, JSONL audit events, and the
  experiment report

## Build and run

The kernel must expose BTF and have the BPF LSM enabled. The monitor and its
loader require root privileges. Build libbpf from the commit recorded above,
then compile the BPF object and userspace programs using the commands documented
in `results/EXPERIMENT_REPORT.md`.

Run:

```bash
sudo bash bpf/run_bpf_smoke_test.sh
sudo bash bpf/run_bypass_trials.sh
sudo bash bpf/run_bpf_trials.sh
python3 bpf/analyze_trials.py
```

The scripts operate on synthetic temporary files only. Review their target
paths before running them on a different host.

## Interpreting the evidence

The bypass matrix tests one protected inode and common direct, alias, rename,
and unlink operations. The latency values are microbenchmark results, not a
claim about end-to-end coding-agent throughput. Generalization to other kernels,
filesystems, mount layouts, containers, or concurrent policy changes requires
new experiments.
