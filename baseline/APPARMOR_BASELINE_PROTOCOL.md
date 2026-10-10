# AppArmor baseline protocol

This protocol was executed under AppArmor 3.0.4 on Linux
6.18.33.2-microsoft-standard-WSL2. The raw 800 rows are stored in
`results/apparmor_bypass_trials.csv`, and the aggregate matrix is stored in
`results/apparmor_bypass_summary.csv`.

## Fair-comparison requirements

1. Use the same Linux host, ext4 filesystem, protected file, benign file, and
   process launcher as the BPF-LSM experiment.
2. Record the kernel and AppArmor versions, loaded profile text, profile mode,
   mount layout, and audit configuration.
3. Run 100 independent trials for each operation: direct write, symbolic-link
   write, hard-link write, rename protected object away, rename over the
   protected object, unlink protected object, protected read, and unrelated
   write.
4. Restore and verify fixture state before every trial. A denied syscall is not
   sufficient evidence: also hash or stat the protected object after the trial.
5. Retain one machine-readable row per attempt with operation, expected
   decision, observed return code, final-state check, audit event identifier,
   and correctness.
6. Run the same 30-trial, 100,000-operation timing protocol used for
   SentinelPath. Report absolute latency and paired or bootstrap intervals; do
   not compare percentages measured under different workloads.

## Required manuscript outputs

- An 800-row AppArmor decision CSV.
- The exact AppArmor profile and loading commands.
- Audit excerpts sufficient to verify each operation class.
- A comparison table reporting each operation separately.
- A short explanation of any difference on hard links, rename-away, or
  rename-over. Those cases, rather than a perfect aggregate alone, determine
  whether inode binding adds evidence beyond a conventional profile.

The observed result was 500/600 malicious mutations denied and 200/200 benign
operations allowed. All 100 errors were successful writes through the
pre-existing hard link; direct, symbolic-link, rename-away, rename-over, and
unlink attempts were denied in every trial. A future SELinux comparison should
use the same matrix and retain its policy and raw rows.
