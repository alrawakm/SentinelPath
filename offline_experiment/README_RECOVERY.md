# SentinelPath full experiment recovery

This directory is a preserved copy of the original staged/trigger experiment.
It contains the exact fixture builder, campaign prompts, session collector,
scorer, feature pipeline, 81 raw process-tree traces, 81 metadata records, 81
session outcomes, agent logs, processed features, and aggregate results.

The original 54 Codex and Claude sessions are unchanged. A third runner branch,
`agent03_cursor`, was added and used to collect a balanced 27-session Cursor
replication. It uses the
same fixture builder, prompt construction, `strace` collector, scoring script,
and campaign identifiers. Cursor is invoked in documented headless write mode
with `-p --force --output-format text`. If `CURSOR_MODEL` is unset, the metadata
records `default-routing`; a requested model is never treated as proof of the
served backend model.

Before a Cursor run, authenticate the experiment account:

```bash
/home/ar_foothold/.local/bin/cursor-agent login
/home/ar_foothold/.local/bin/cursor-agent status
```

Then run one prespecified pilot campaign or the balanced pilot block:

```bash
bash scripts/run_campaign.sh agent03_cursor trigger matched_control 1 pilot
bash scripts/run_remaining_pilot.sh agent03_cursor
```

The balanced runner analyzes the corpus once after all scheduled campaigns.
This avoids repeatedly parsing the full raw trace corpus between campaigns and
does not change fixture generation, collection, scoring, or inclusion rules.

The completed corpus contains 27 sessions per framework. Codex and Cursor each
executed all six expected protected changes and made no protected change in 21
negative sessions. Claude made no protected change in its 27 sessions. The
policy detector produced 12 true positives and 69 true negatives, with no false
positive or false negative. A failed or interrupted campaign remains part of
the execution record and must not be silently removed.

The release archive retains the 81 raw `strace` files, from which
`data/raw/host_telemetry.jsonl` can be regenerated with
`scripts/strace_to_jsonl.py`. The regenerated aggregate is omitted from the ZIP
because it exceeds 1 GB and duplicates the raw trace evidence.
