"""Ask AWS VPC Reachability Analyzer whether traffic can get from A to B.

Reachability Analyzer models security groups, NACLs, route tables and gateways
together, so its answer is the source of truth. The AI in later milestones calls
check_path() as a tool and must cite its result.

Each analysis costs about $0.10, so the CLI shows the count and asks first, and
every path and analysis is deleted afterwards.

Usage (CloudShell, repo root, lab deployed, AUDITOR_ROLE_ARN exported):
    python3 baseline/reachability.py --source internet --destination web --port 80
    python3 baseline/reachability.py --all --out docs/results/m3-reachability.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collector"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

COST_PER_ANALYSIS = 0.10


# ---------- explanation parsing ----------

# Most specific first. An explanation often lists several components (for a
# security group mismatch: the ENI, its security groups, the subnet and the VPC),
# and the one that actually decided the outcome is the rule-bearing one.
COMPONENT_KEYS = [
    "Acl", "SecurityGroups", "SecurityGroup", "RouteTable", "InternetGateway",
    "NatGateway", "NetworkInterface", "Component", "Destination", "Subnet", "Vpc",
]


def build_name_map(snapshot: dict) -> dict[str, str]:
    """AWS ID -> Name tag (or group name) from a collector snapshot."""
    names = {}
    for section in ["internet_gateways", "subnets", "route_tables", "network_acls", "security_groups", "instances"]:
        for item in snapshot.get(section, []):
            if item.get("name"):
                names[item["id"]] = item["name"]
    if snapshot.get("vpc", {}).get("name"):
        names[snapshot["vpc"]["id"]] = snapshot["vpc"]["name"]
    return names


def summarize_explanation(exp: dict, names: dict[str, str] | None = None) -> dict:
    """Pick the useful parts out of one Reachability Analyzer explanation."""
    names = names or {}
    out = {"code": exp.get("ExplanationCode")}
    for key in COMPONENT_KEYS:
        comp = exp.get(key)
        comps = comp if isinstance(comp, list) else [comp] if comp else []
        comps = [c for c in comps if c and c.get("Id")]
        if comps:
            ids = [c["Id"] for c in comps]
            out["component_type"] = key.rstrip("s") if key == "SecurityGroups" else key
            out["component_id"] = ", ".join(ids)
            labels = [c.get("Name") or names.get(c["Id"]) for c in comps]
            if all(labels):
                out["component_name"] = ", ".join(labels)
            break
    rule = exp.get("AclRule")
    if rule:
        ports = rule.get("PortRange") or {}
        out["acl_rule"] = {
            "rule_number": rule.get("RuleNumber"),
            "action": rule.get("RuleAction"),
            "protocol": rule.get("Protocol"),
            "ports": [ports.get("From"), ports.get("To")] if ports else None,
            "cidr": rule.get("Cidr"),
            "egress": rule.get("Egress"),
        }
    return out


def describe_blocker(explanations: list[dict]) -> str:
    if not explanations:
        return "no explanation returned"
    parts = []
    for e in explanations:
        where = e.get("component_name") or e.get("component_id") or "unknown component"
        text = f"{e['code']} at {where}"
        if "acl_rule" in e:
            text += f" (rule {e['acl_rule']['rule_number']} {e['acl_rule']['action']})"
        parts.append(text)
    return "; ".join(parts)


# ---------- the analyzer call ----------

def check_path(ec2, source_id: str, destination_id: str, port: int, protocol: str = "tcp",
               timeout: int = 300, poll: float = 3.0, sleep=time.sleep,
               names: dict[str, str] | None = None) -> dict:
    """Run one analysis and always clean up. Returns a plain dict the AI can cite."""
    path_id = analysis_id = None
    try:
        path_id = ec2.create_network_insights_path(
            Source=source_id, Destination=destination_id,
            Protocol=protocol, DestinationPort=port,
        )["NetworkInsightsPath"]["NetworkInsightsPathId"]

        analysis_id = ec2.start_network_insights_analysis(
            NetworkInsightsPathId=path_id,
        )["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"]

        waited = 0.0
        while True:
            analysis = ec2.describe_network_insights_analyses(
                NetworkInsightsAnalysisIds=[analysis_id],
            )["NetworkInsightsAnalyses"][0]
            if analysis["Status"] != "running":
                break
            if waited >= timeout:
                raise TimeoutError(f"analysis {analysis_id} still running after {timeout}s")
            sleep(poll)
            waited += poll

        if analysis["Status"] != "succeeded":
            raise RuntimeError(f"analysis failed: {analysis.get('StatusMessage', analysis['Status'])}")

        explanations = [summarize_explanation(e, names) for e in analysis.get("Explanations", [])]
        reachable = bool(analysis.get("NetworkPathFound"))
        return {
            "source": source_id,
            "destination": destination_id,
            "protocol": protocol,
            "port": port,
            "reachable": reachable,
            "explanations": explanations,
            "blocked_by": None if reachable else describe_blocker(explanations),
            "path_components": [
                c["Component"]["Id"] for c in analysis.get("ForwardPathComponents", [])
                if c.get("Component", {}).get("Id")
            ],
            "analysis_id": analysis_id,
        }
    finally:
        for call, arg in [
            (getattr(ec2, "delete_network_insights_analysis", None), {"NetworkInsightsAnalysisId": analysis_id}),
            (getattr(ec2, "delete_network_insights_path", None), {"NetworkInsightsPathId": path_id}),
        ]:
            if call and list(arg.values())[0]:
                try:
                    call(**arg)
                except Exception as err:  # cleanup must never hide the real result or error
                    print(f"warning: cleanup failed for {arg}: {err}", file=sys.stderr)


# ---------- resolving roles to AWS IDs ----------

def resolve(snapshot: dict, role: str) -> str | None:
    """internet -> IGW id, web/db -> instance id, vpc -> None (no single host to test from)."""
    if role == "internet":
        return snapshot["internet_gateways"][0]["id"]
    if role == "vpc":
        return None
    for inst in snapshot["instances"]:
        if inst.get("role") == role:
            return inst["id"]
    raise SystemExit(f"No instance with Role tag {role!r} in the snapshot")


# ---------- CLI ----------

def confirm(n: int, assume_yes: bool) -> bool:
    print(f"About to run {n} Reachability Analyzer analys{'is' if n == 1 else 'es'} "
          f"(about ${n * COST_PER_ANALYSIS:.2f}).")
    if assume_yes:
        return True
    return input("Continue? [y/N] ").strip().lower() in ("y", "yes")


def main(argv: list[str] | None = None) -> int:
    from checks import expected_bool, load_answer_key, newest_snapshot, score_answers, yes_no
    from collect import make_session

    parser = argparse.ArgumentParser(description="Reachability Analyzer wrapper")
    parser.add_argument("--role-arn", default=os.environ.get("AUDITOR_ROLE_ARN"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--snapshot", type=Path, help="Snapshot used to map roles to IDs (default: newest)")
    parser.add_argument("--answer-key", type=Path, default=Path("answer_key/expected_findings.yaml"))
    parser.add_argument("--source", help="internet, web or db")
    parser.add_argument("--destination", help="web or db")
    parser.add_argument("--port", type=int)
    parser.add_argument("--all", action="store_true", help="Run every answer-key question that has a single source")
    parser.add_argument("--yes", action="store_true", help="Skip the cost confirmation")
    parser.add_argument("--out", type=Path, help="Write results JSON here")
    args = parser.parse_args(argv)

    if not args.role_arn:
        print("error: pass --role-arn or set AUDITOR_ROLE_ARN", file=sys.stderr)
        return 2

    snapshot = json.loads((args.snapshot or newest_snapshot()).read_text())

    if args.all:
        key = load_answer_key(args.answer_key)
        questions = key["reachability_questions"]
    elif args.source and args.destination and args.port:
        key = None
        questions = [{"id": "adhoc", "question": f"{args.source} -> {args.destination} tcp/{args.port}",
                      "source": args.source, "destination": args.destination, "port": args.port}]
    else:
        parser.error("pass --all, or --source, --destination and --port")

    runnable = [q for q in questions if resolve(snapshot, q["source"]) is not None]
    if not confirm(len(runnable), args.yes):
        print("Cancelled.")
        return 1

    ec2 = make_session(args.role_arn, args.region).client("ec2")
    names = build_name_map(snapshot)
    results, answers = [], {}
    for q in questions:
        src = resolve(snapshot, q["source"])
        if src is None:
            print(f"  skip  {q['id']} {q['question']} (needs a concrete source host)")
            answers[q["id"]] = None
            continue
        r = check_path(ec2, src, resolve(snapshot, q["destination"]), q["port"], names=names)
        answers[q["id"]] = r["reachable"]
        results.append({"question_id": q["id"], "question": q["question"], **r})
        verdict = "REACHABLE" if r["reachable"] else "blocked"
        expected = f" (expected {yes_no(expected_bool(q))})" if "expected" in q else ""
        detail = "" if r["reachable"] else f": {r['blocked_by']}"
        print(f"  {q['id']} {q['question']} -> {verdict}{expected}{detail}")

    score = None
    if key:
        score = score_answers(answers, key)
        answered = len(score["correct"]) + len(score["wrong"])
        print(f"\nCorrect {len(score['correct'])}/{answered} answered"
              f"{', wrong: ' + ', '.join(score['wrong']) if score['wrong'] else ''}"
              f"{', skipped: ' + ', '.join(score['skipped']) if score['skipped'] else ''}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"tool": "reachability-analyzer", "results": results,
                                        "answer_score": score}, indent=2) + "\n")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
