# Native-Linux baseline extension protocol

This protocol is supplied for the next experiment. A baseline must not be
entered in the manuscript result table until the commands, post-state checks,
security-module records, and environment metadata have been retained.

## Preflight

Run `baseline/check_baseline_capabilities.sh OUTPUT TEST_PATH` on a native Linux host, where
`TEST_PATH` is the filesystem used for the operation matrix. Record the
kernel, filesystem, active LSM order, policy mode, policy package version, and
the exact policy files. Do not replace or reorder the host's global LSM list on
a production machine.

## Shared matrix

Use the same eight cells and 100 independent attempts per cell as the existing
BPF-LSM and AppArmor experiments: direct write, symbolic-link write,
pre-existing hard-link write, rename away, atomic rename over, unlink,
protected read, and unrelated write. Recreate the fixture before every attempt.
For every row retain the command return code, expected decision, protected-file
existence, protected-file content hash, inode and device before and after the
operation, and the corresponding policy log identifier.

## SELinux baseline

Use an enforcing native-Linux installation with a dedicated test domain and a
dedicated protected-object type. Grant the domain the minimum permissions
needed for the fixture and deny mutation permissions for the protected type.
Label the protected object before aliases are created. Retain the `.te`, `.if`,
and `.fc` files, compiled policy checksum, `sestatus`, `semodule -lfull`, file
contexts, and AVC records. Report both command-decision correctness and
post-state correctness. The hard-link cell must state whether the alias kept the
same SELinux type and inode; a pathname-only interpretation is not sufficient.

## Linux Audit comparator

Linux Audit is an observation baseline, not a denial baseline. Add an inode- or
path-relevant rule for the protected object, run the same matrix without
claiming prevention, and score whether each relevant operation produced a
complete, correlatable record. Retain the rule listing and the serial identifiers
joining SYSCALL, PATH, CWD, and PROCTITLE records.

## IMA/EVM and fapolicyd

Evaluate these only for claims their mechanisms can support. IMA/EVM should be
scored for measurement or appraisal of integrity changes and retained xattr
evidence. fapolicyd should be scored for execution or open-policy decisions
under its configured trust rules. Neither result should be relabeled as a
general replacement for SELinux write mediation.

## Reporting rule

Do not pool repeated operations as independent agent executions. Report the
operation matrix as deterministic compatibility evidence. Report agent-level
sensitivity only from independently executed agent sessions, with the agent,
version, task family, and trial unit stated explicitly.
