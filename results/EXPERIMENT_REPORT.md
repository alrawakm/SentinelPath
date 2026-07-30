# SentinelPath Online Enforcement Experiment

## Status

The BPF-LSM prototype successfully mediated protected-file mutations in the
local WSL2 laboratory. The earlier Fanotify prototype is retained only as a
negative engineering result: its event descriptor did not expose the original
open access mode reliably, and its apparent enforcement test failed.

## Environment

- Kernel: Linux 6.18.33.2-microsoft-standard-WSL2
- Active LSM order: capability, landlock, yama, safesetid, selinux, bpf, ima
- Compiler: Ubuntu Clang 14.0.0 and GCC 11.4.0
- libbpf revision: `f7081a6baf3f54949aacb8c2fc11bb30783b83e9`
- Protected object: one regular JSON file identified by kernel device and inode
- Authorization scope: one PID-namespace TGID launched through
  `sentinelpath_run`

## Enforcement Design

The kernel program attaches to four LSM hooks:

1. `file_open` denies unauthorized write-mode opens.
2. `file_permission` denies unauthorized write operations on an already open
   descriptor.
3. `inode_unlink` denies deletion of the protected inode.
4. `inode_rename` denies moving the protected inode or replacing it through an
   atomic rename.

The target key is the pair `(kernel dev_t, inode)`. Userspace converts
`st_dev` to the kernel's 20-bit-minor representation. Process authorization is
resolved in the WSL PID namespace with `bpf_get_ns_current_pid_tgid`; using the
host TGID produced an observed namespace mismatch and was rejected during
development.

## Functional Results

The final smoke test produced the following verified sequence:

- Unauthorized write-mode open: denied.
- Authorized write-mode open: allowed.
- Authorized write syscall: allowed.
- Unauthorized unlink: denied.

The repeated bypass matrix contained 100 attempts per condition:

| Case | Expected | Correct | Incorrect |
|---|---:|---:|---:|
| Direct protected write | Deny | 100 | 0 |
| Symlink write | Deny | 100 | 0 |
| Hardlink write | Deny | 100 | 0 |
| Rename protected inode away | Deny | 100 | 0 |
| Atomic rename over protected inode | Deny | 100 | 0 |
| Unlink protected inode | Deny | 100 | 0 |
| Protected read | Allow | 100 | 0 |
| Unrelated write | Allow | 100 | 0 |

Across these trials, all 600 mutation attempts were denied and all 200 benign
operations were allowed. The timing experiment independently recorded 30,000
denied opens, 30,000 authorized opens, and 30,000 authorized writes in the
kernel audit stream.

## Timing Results

Each condition was repeated for 30 trials. The table reports mean nanoseconds
per operation and a seeded 10,000-resample percentile bootstrap confidence
interval for the mean.

| Condition | Mean ns/op | SD | Median | Bootstrap 95% CI |
|---|---:|---:|---:|---:|
| Baseline read | 5,841 | 945 | 5,772 | 5,527--6,191 |
| Baseline write | 6,349 | 702 | 6,344 | 6,102--6,600 |
| Monitored unrelated write | 6,663 | 709 | 6,625 | 6,419--6,912 |
| Protected read | 5,898 | 461 | 5,944 | 5,736--6,061 |
| Protected unauthorized write | 4,544 | 1,102 | 4,124 | 4,171--4,949 |
| Protected authorized write | 12,445 | 4,513 | 10,934 | 10,903--14,098 |

Relative to the corresponding baseline and pairing trials by index:

- An unrelated write while SentinelPath was loaded incurred 6.12% mean
  overhead (bootstrap 95% CI: 0.65%--11.98%; median overhead 5.44%).
- A protected read incurred 3.23% mean overhead (bootstrap 95% CI:
  -2.76%--9.35%; median overhead 1.14%).
- An authorized protected write with two audit events incurred 96.98% mean
  overhead (bootstrap 95% CI: 72.74%--123.12%; median overhead 65.11%).
- A denied write completed 27.78% faster than a successful baseline write
  because rejection occurs before storage I/O. This is denial latency, not a
  negative enforcement overhead claim.

## Reproducibility Files

- `sentinelpath.bpf.c`: kernel LSM programs and maps.
- `sentinelpath_loader.c`: target configuration, attachment, and JSONL audit.
- `sentinelpath_run.c`: PID-namespace-scoped authorized launcher.
- `io_benchmark.c`: monotonic-clock read/write worker.
- `run_bpf_smoke_test.sh`: minimal allow/deny test.
- `run_bypass_trials.sh`: repeated bypass and compatibility matrix.
- `run_bpf_trials.sh`: 30-trial timing experiment.
- `analyze_trials.py`: deterministic bootstrap analysis.
- `trial_metrics.csv`: raw per-trial timings.
- `trial_summary.csv`: condition summaries.
- `trial_comparisons.csv`: overhead comparisons.
- `bypass_trials.csv`: repeated functional outcomes.
- `trial_events.jsonl`: 90,000 kernel audit decisions.

## Limitations

These results establish a functioning prototype, not universal deployment
validity. The experiment used one WSL2 kernel, one ext4 filesystem, root-run
test processes, one protected inode at a time, and synthetic local I/O. It did
not test containers with distinct PID namespaces, network filesystems,
high-concurrency races, crash recovery while enforcement is active, or
production agent workloads. The 30 timing trials were executed on one machine
in one session and may contain temporal dependence. Broader claims require
multi-kernel, multi-filesystem, concurrent, and application-level validation.

## Engineering Incident

An intentionally temporary diagnostic version initially emitted an event for
every write. Because the userspace event handler wrote those events to a file,
it created recursive logging and caused the WSL virtual disk to abort its ext4
journal and remount read-only. All experiment processes were stopped, WSL was
rebooted, ext4 reported `recovery complete`, the filesystem remounted
read/write, and a write/delete health probe passed. The final program emits
events only for the configured target inode and does not contain the recursive
diagnostic path.
