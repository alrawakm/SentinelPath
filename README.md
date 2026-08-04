# SentinelPath reproducibility package

This repository contains the source, raw observations, and analysis scripts
for the SentinelPath offline detector, BPF-LSM enforcement experiment, and
AppArmor and SELinux baselines. It
does not contain the manuscript, LaTeX source, PDFs, or Overleaf files.

## Offline three-framework experiment

The `offline_experiment/` directory contains the complete 81-session corpus:

- 27 OpenAI Codex sessions
- 27 Anthropic Claude Code sessions
- 27 Cursor Agent sessions
- 81 raw process-tree `strace` files
- 81 pre-execution metadata records and 81 independently scored outcomes
- 80 available agent-output logs
- the fixture builder, exact campaign runner, collector, scorer, feature
  pipeline, policy detector, and learned-model evaluator
- processed features and machine-readable detector and model results

The policy detector produced 12 true positives and 69 true negatives, with no
false positive or false negative. The large derived
`data/raw/host_telemetry.jsonl` file is intentionally omitted because it exceeds
1 GB and can be regenerated from the 81 committed raw traces.

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

## Native Fedora SELinux baseline

The `selinux/` directory contains the policy source, file-context rules, static
operation runner source, and exact 800-trial harness. The baseline was executed
on Fedora 43, Linux `6.17.1-300.fc43.x86_64`, Btrfs, with the targeted SELinux
policy in enforcing mode. It used 100 attempts in each of six deny-expected and
two allow-expected cells.

SELinux denied all 600 protected mutations and allowed all 200 benign
operations. Decision and post-state checks passed in all 800 rows. The hard-link
and protected path shared the same device, inode, and protected SELinux type.
The bounded audit extract contains 600 AVC records. Raw rows, the aggregate,
environment evidence, timestamps, audit records, and checksums are under
`results/selinux/`.

## Layout

- `bpf/`: BPF program, userspace loader and launcher, benchmarks, trial scripts,
  and analysis
- `results/`: raw and summarized CSV data, JSONL audit events, and the
  experiment report
- `offline_experiment/`: three-framework fixture, runners, raw traces,
  metadata, scored outcomes, processed features, and evaluation outputs
- `selinux/`: native-Fedora SELinux policy, operation runner, and matrix script
- `results/selinux/`: raw 800-trial matrix, summary, bounded AVC log,
  environment record, timestamps, and checksums

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

For the SELinux baseline on Fedora, install `gcc`, `glibc-static`,
`selinux-policy-devel`, `policycoreutils-devel`, and `audit`, then run:

```bash
cd selinux
gcc -O2 -Wall -Wextra -static -o sentinelpath_op sentinelpath_op.c
make -f /usr/share/selinux/devel/Makefile sentinelpath_selinux.pp
sudo install -D -m 0755 sentinelpath_op /usr/local/libexec/sentinelpath_op
sudo semodule -i sentinelpath_selinux.pp
sudo restorecon -v /usr/local/libexec/sentinelpath_op
ATTEMPTS=100 bash run_selinux_matrix.sh selinux_trials_800.csv
```

## Interpreting the evidence

The bypass matrix tests one protected inode and common direct, alias, rename,
and unlink operations. The latency values are microbenchmark results, not a
claim about end-to-end coding-agent throughput. Generalization to other kernels,
filesystems, mount layouts, containers, or concurrent policy changes requires
new experiments.
