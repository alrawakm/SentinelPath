# SentinelPath reproducibility package

This repository contains the source, raw observations, analysis scripts, and
paper files for the SentinelPath BPF-LSM enforcement experiment and the two
mandatory-access-control baselines it is compared against.

## Reported online (BPF-LSM) experiment

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

## Reported AppArmor baseline

AppArmor 3.0.4 on the same WSL2/ext4 kernel, booted with the LSM stack in
`baseline/wslconfig_apparmor_bpf`, running the profile in
`baseline/sentinelpath-apparmor.profile`. Same eight operation classes, 100
attempts each (`results/apparmor_bypass_trials.csv`,
`results/apparmor_bypass_summary.csv`). The profile names the protected
pathname; the 100 hard-link-write failures are the result the paper reports.

## Reported SELinux baseline

A custom type-enforcement policy (`baseline/selinux/sentinelpath_selinux.te`
and the generated `.fc`/`.if`/`.pp`) on native Fedora 43 with a Btrfs root and
SELinux in enforcing mode. Same eight operation classes, 100 attempts each
(`results/selinux/selinux_trials_800.csv`,
`results/selinux/selinux_summary_800.csv`), plus the raw AVC audit log
(`results/selinux/selinux_avc_800.log`) and the environment/run records.

## Layout

- `bpf/`: BPF program, userspace loader and launcher, benchmarks, trial scripts,
  and analysis for the online enforcement path
- `baseline/`: AppArmor profile, boot config, trial runner, and protocol notes;
  `baseline/selinux/` holds the SELinux policy module source and its runner
- `results/`: raw and summarized CSV data, JSONL audit events, and the
  experiment report for all three mechanisms; `results/selinux/` holds the
  SELinux-specific audit log and environment records

## Build and run

**BPF-LSM.** The kernel must expose BTF and have the BPF LSM enabled. The
monitor and its loader require root privileges. Build libbpf from the commit
recorded above, then compile the BPF object and userspace programs using the
commands documented in `results/EXPERIMENT_REPORT.md`.

```bash
sudo bash bpf/run_bpf_smoke_test.sh
sudo bash bpf/run_bypass_trials.sh
sudo bash bpf/run_bpf_trials.sh
python3 bpf/analyze_trials.py
```

**AppArmor.** Requires an AppArmor-enabled kernel, the AppArmor parser, and
`aa-exec`. See `baseline/APPARMOR_BASELINE_PROTOCOL.md` for the full procedure.

```bash
sudo bash baseline/check_baseline_capabilities.sh
sudo bash baseline/run_apparmor_trials.sh
```

**SELinux.** Requires a native SELinux system in enforcing mode with
permission to install a local policy module. See
`baseline/BASELINE_EXTENSION_PROTOCOL.md` for the full procedure.

```bash
sudo bash baseline/selinux/run_selinux_matrix.sh
```

All scripts operate on synthetic temporary files only. Review their target
paths before running them on a different host.

## Interpreting the evidence

The bypass matrix tests one protected inode and common direct, alias, rename,
and unlink operations. The latency values are microbenchmark results, not a
claim about end-to-end coding-agent throughput. Generalization to other kernels,
filesystems, mount layouts, containers, or concurrent policy changes requires
new experiments. The AppArmor and SELinux baselines were each run on their own
host and kernel; the comparison is at the level of operation outcomes, not a
controlled latency comparison across mechanisms.
