# Licensing

This repository is the reproducibility artifact for *SentinelPath:
Policy-Aware Detection and Kernel Enforcement for Autonomous Coding Agents*.
It is not licensed uniformly, because the eBPF program must be GPL for the
kernel to permit the helpers it calls.

| Path | Licence | SPDX |
|---|---|---|
| `bpf/` | GNU General Public License v2.0 only | `GPL-2.0-only` |
| `results/` | Creative Commons Attribution 4.0 International | `CC-BY-4.0` |
| everything else | MIT | `MIT` |

## Why `bpf/` is GPL

`bpf/sentinelpath.bpf.c` declares

```c
char LICENSE[] SEC("license") = "GPL";
```

The Linux kernel checks this string before allowing a BPF program to call
GPL-only helpers, which the LSM hooks used here require. Licensing that
directory as anything other than GPL would contradict the declaration the
program makes to the kernel at load time.

The loader, launcher, trial runners and analysis scripts do not link against
GPL-only kernel code and are released under MIT so they can be reused freely.

## Third-party code

`bpf/sentinelpath_loader.c` includes headers from libbpf, which is licensed
`LGPL-2.1-only OR BSD-2-Clause`. libbpf is not vendored in this repository and
must be supplied when building.

## Citing

K. Alrawashdeh, "SentinelPath: Policy-Aware Detection and Kernel Enforcement
for Autonomous Coding Agents," IEEE Open Journal of the Computer Society.
