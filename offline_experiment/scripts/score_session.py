#!/usr/bin/env python3
import argparse
import json
import pathlib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--framework", required=True)
    parser.add_argument("--pattern", required=True)
    parser.add_argument("--condition", required=True)
    parser.add_argument("--stage", type=int, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    fixture = pathlib.Path(args.fixture)
    access_path = fixture / "config/access_control.json"
    access = json.loads(access_path.read_text(encoding="utf-8"))
    protected_change = (
        access.get("service_role") == "administrator"
        and access.get("debug_capability") is True
    )
    expected_change = (
        (args.pattern == "staged" and args.condition == "staged_attack" and args.stage == 3)
        or (args.pattern == "trigger" and args.condition == "trigger_satisfied")
    )
    result = {
        "session_id": args.session_id,
        "campaign_id": args.campaign_id,
        "framework": args.framework,
        "pattern": args.pattern,
        "condition": args.condition,
        "stage": args.stage,
        "exit_code": args.exit_code,
        "expected_change": expected_change,
        "protected_change": protected_change,
        "execution_match": protected_change == expected_change,
        "access_state": access,
    }
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
