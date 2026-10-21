"""Prove an applied fix worked, using the same evidence that found the problem.

Two independent checks, whichever apply to the finding:
  - rule level: the baseline scanner no longer reports the finding on a fresh snapshot
  - path level: Reachability Analyzer re-runs the "before" path and gets the expected result

Usage (CloudShell, repo root), after `git apply`, `terraform apply` and a fresh collect:
    python3 auditor/verify_fix.py P1
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("auditor", "baseline", "collector"):
    sys.path.insert(0, str(ROOT / sub))

from reachability import COST_PER_ANALYSIS, build_name_map, check_path, resolve  # noqa: E402


def patch_is_applied(patch: Path) -> bool | None:
    """True if the patch is in the working tree, False if not, None if git can't tell."""
    git = shutil.which("git")
    if not git or not patch.exists():
        return None
    r = subprocess.run([git, "-C", str(ROOT), "apply", "--reverse", "--check", str(patch.resolve())],
                       capture_output=True, text=True)
    return r.returncode == 0


def describe(result: dict | None) -> str:
    if result is None:
        return "-"
    return "reachable" if result["reachable"] else f"blocked ({result['blocked_by']})"


def evaluate(record: dict, snapshot: dict, answer_key: dict, run_check) -> dict:
    """Pure decision logic, separate from AWS so it can be tested offline."""
    from checks import run_checks, score_findings

    fid = record["finding_id"]
    out = {"rule_level": None, "path_level": None}

    if record.get("baseline_caught_before"):
        still = fid in score_findings(run_checks(snapshot), answer_key)["caught"]
        out["rule_level"] = {"passed": not still,
                             "detail": "baseline still reports the finding" if still
                             else "baseline no longer reports the finding"}

    spec = record.get("verify")
    if spec:
        after = run_check(spec)
        want_reachable = spec["after"] == "reachable"
        out["path_level"] = {"passed": after["reachable"] == want_reachable,
                             "expected": spec["after"], "after": after}

    checks_run = [v for v in out.values() if v is not None]
    out["passed"] = bool(checks_run) and all(v["passed"] for v in checks_run)
    return out


def main(argv: list[str] | None = None) -> int:
    from checks import load_answer_key, newest_snapshot
    from collect import make_session

    parser = argparse.ArgumentParser(description="Verify an applied fix with before/after evidence")
    parser.add_argument("finding", help="Finding ID, e.g. P1")
    parser.add_argument("--role-arn", default=os.environ.get("AUDITOR_ROLE_ARN"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--answer-key", type=Path, default=ROOT / "answer_key" / "expected_findings.yaml")
    parser.add_argument("--results-dir", type=Path, default=Path("docs/results"))
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)

    fid = args.finding.upper()
    record_path = args.results_dir / f"m5-{fid}.json"
    if not record_path.exists():
        print(f"error: {record_path} not found. Run propose_fix.py {fid} first.", file=sys.stderr)
        return 2
    record = json.loads(record_path.read_text())

    applied = patch_is_applied(Path(record["patch_file"]))
    if applied is False:
        print("warning: the patch does not appear to be applied in this working tree "
              f"(git apply {record['patch_file']}).", file=sys.stderr)

    snap_path = args.snapshot or newest_snapshot()
    snapshot = json.loads(snap_path.read_text())
    if snapshot["collected_at"] <= record["created_at"]:
        print("error: the newest snapshot was taken before the fix was proposed, so it can't show the fix.\n"
              "Run `terraform apply` with the patch, then `python3 collector/collect.py`, then retry.",
              file=sys.stderr)
        return 2

    spec = record.get("verify")
    if spec:
        if not args.role_arn:
            print("error: pass --role-arn or set AUDITOR_ROLE_ARN", file=sys.stderr)
            return 2
        print(f"Verifying {fid} with one Reachability Analyzer run (about ${COST_PER_ANALYSIS:.2f}).")
        if not args.yes and input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            return 1
        ec2 = make_session(args.role_arn, args.region).client("ec2")
    names = build_name_map(snapshot)

    def run_check(s):
        return check_path(ec2, resolve(snapshot, s["source"]), resolve(snapshot, s["destination"]),
                          s["port"], names=names)

    result = evaluate(record, snapshot, load_answer_key(args.answer_key), run_check)
    record["verification"] = {"snapshot": str(snap_path), "patch_applied": applied, **result}
    record_path.write_text(json.dumps(record, indent=2, default=str) + "\n")

    print(f"\n{fid}: {record['title']}  ({record['action']} {record['resource']})")
    if result["path_level"]:
        p = result["path_level"]
        print(f"  Path   {spec['source']} -> {spec['destination']} tcp/{spec['port']}")
        print(f"    before: {describe(record.get('before'))}")
        print(f"    after:  {describe(p['after'])}   (expected {p['expected']})  "
              f"{'PASS' if p['passed'] else 'FAIL'}")
    if result["rule_level"]:
        r = result["rule_level"]
        print(f"  Rule   {r['detail']}  {'PASS' if r['passed'] else 'FAIL'}")
    if not result["path_level"] and not result["rule_level"]:
        print("  Nothing to verify automatically for this finding.")
    print(f"\nRESULT: {'fix verified' if result['passed'] else 'fix NOT verified'}")
    print(f"wrote {record_path}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
