"""Deterministic baseline: rule-based checks over a collector snapshot, with no AI.

This is deliberately a *naive* scanner, the kind of thing many config linters do:
it reasons about security groups and route tables but ignores NACL ordering.
Its blind spots are the point. Later milestones measure what Reachability
Analyzer and the AI add on top of it.

Usage (repo root):
    python3 baseline/checks.py                       # newest snapshot in snapshots/live/
    python3 baseline/checks.py --snapshot path.json --out docs/results/m3-baseline.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch",
    27017: "MongoDB",
}
DB_PORTS = {1433, 1521, 3306, 5432, 6379, 27017}
WORLD = {"0.0.0.0/0", "::/0"}


# ---------- helpers ----------

def covers_port(rule: dict, port: int) -> bool:
    if rule["protocol"] == "all":
        return True
    if rule["protocol"] != "tcp" or rule["from_port"] is None:
        return False
    return rule["from_port"] <= port <= rule["to_port"]


def index(snapshot: dict) -> dict:
    return {
        "sg": {g["id"]: g for g in snapshot["security_groups"]},
        "subnet": {s["id"]: s for s in snapshot["subnets"]},
        "rt": {r["id"]: r for r in snapshot["route_tables"]},
        "role": {i["role"]: i for i in snapshot["instances"] if i.get("role")},
    }


def has_default_route_to_igw(route_table: dict) -> bool:
    return any(
        r["destination"] == "0.0.0.0/0" and r["target_type"] == "internet_gateway" and r["state"] == "active"
        for r in route_table["routes"]
    )


def finding(check: str, severity: str, detail: str, **where) -> dict:
    return {"check": check, "severity": severity, **where, "detail": detail}


# ---------- checks ----------

def check_world_open(snapshot: dict) -> list[dict]:
    out = []
    for g in snapshot["security_groups"]:
        for r in g["ingress"]:
            if r["source_type"] != "cidr" or r["source"] not in WORLD:
                continue
            if r["protocol"] == "all":
                out.append(finding("all_traffic_open_to_world", "high",
                                   f"all protocols and ports allowed from {r['source']}",
                                   security_group=g["name"]))
                continue
            for port, service in SENSITIVE_PORTS.items():
                if covers_port(r, port):
                    out.append(finding("sensitive_port_open_to_world", "high",
                                       f"{service} (tcp/{port}) allowed from {r['source']}",
                                       security_group=g["name"], port=port))
    return out


def check_db_port_from_cidr(snapshot: dict) -> list[dict]:
    """DB ports should be opened to a security group (the app tier), not an address range."""
    out = []
    for g in snapshot["security_groups"]:
        for r in g["ingress"]:
            if r["source_type"] != "cidr" or r["source"] in WORLD:
                continue  # world-open is already covered above
            if ipaddress.ip_network(r["source"]).num_addresses <= 1:
                continue  # a single /32 host is specific enough
            for port in sorted(DB_PORTS):
                if covers_port(r, port):
                    out.append(finding("db_port_from_cidr", "medium",
                                       f"{SENSITIVE_PORTS[port]} (tcp/{port}) allowed from range {r['source']} "
                                       "instead of a specific security group",
                                       security_group=g["name"], port=port))
    return out


def check_private_subnet_igw(snapshot: dict) -> list[dict]:
    idx = index(snapshot)
    out = []
    for s in snapshot["subnets"]:
        if "private" not in (s.get("name") or "").lower():
            continue
        rt = idx["rt"].get(s["route_table_id"])
        if rt and has_default_route_to_igw(rt):
            out.append(finding("private_subnet_routes_to_igw", "medium",
                               f"subnet named private uses {rt.get('name') or rt['id']}, "
                               "which sends 0.0.0.0/0 to an internet gateway",
                               subnet=s["name"], route_table=rt.get("name") or rt["id"]))
    return out


CHECKS = [check_world_open, check_db_port_from_cidr, check_private_subnet_igw]


def run_checks(snapshot: dict) -> list[dict]:
    return [f for check in CHECKS for f in check(snapshot)]


# ---------- naive reachability (security groups + routes, NO NACLs) ----------

def sg_allows(groups: list[dict], port: int, *, from_ip: str | None = None,
              from_sgs: set[str] = frozenset(), from_net: str | None = None) -> bool:
    for g in groups:
        for r in g["ingress"]:
            if not covers_port(r, port):
                continue
            if r["source_type"] == "security_group" and r["source"] in from_sgs:
                return True
            if r["source_type"] != "cidr":
                continue
            rule_net = ipaddress.ip_network(r["source"])
            if from_ip and ipaddress.ip_address(from_ip) in rule_net:
                return True
            if from_net:
                net = ipaddress.ip_network(from_net)
                if net.version == rule_net.version and net.subnet_of(rule_net):
                    return True
    return False


def naive_reachable(snapshot: dict, source: str, destination: str, port: int) -> tuple[bool, str]:
    idx = index(snapshot)
    dest = idx["role"][destination]
    dest_groups = [idx["sg"][gid] for gid in dest["security_group_ids"]]

    if source == "internet":
        if not dest.get("public_ip"):
            return False, f"{destination} has no public IP"
        rt = idx["rt"][idx["subnet"][dest["subnet_id"]]["route_table_id"]]
        if not has_default_route_to_igw(rt):
            return False, f"{destination}'s subnet has no route to an internet gateway"
        if sg_allows(dest_groups, port, from_ip="8.8.8.8"):
            return True, f"security group allows tcp/{port} from the internet (NACLs not checked)"
        return False, f"no security group rule allows tcp/{port} from the internet"

    if source == "vpc":
        if sg_allows(dest_groups, port, from_net=snapshot["vpc"]["cidr"]):
            return True, f"security group allows tcp/{port} from the whole VPC range"
        return False, f"no rule allows tcp/{port} from every address in the VPC"

    src = idx["role"][source]
    if sg_allows(dest_groups, port, from_ip=src["private_ip"], from_sgs=set(src["security_group_ids"])):
        return True, f"security group allows tcp/{port} from {source} (NACLs not checked)"
    return False, f"no security group rule allows tcp/{port} from {source}"


# ---------- scoring ----------

def load_answer_key(path: Path) -> dict:
    import yaml  # imported here so the checks themselves need only the standard library
    return yaml.safe_load(path.read_text())


def matches(found: dict, expected_match: dict) -> bool:
    return all(found.get(k) == v for k, v in expected_match.items())


def score_findings(found: list[dict], answer_key: dict) -> dict:
    caught, missed, used = [], [], set()
    for item in answer_key["findings"]:
        hit = next((i for i, f in enumerate(found) if matches(f, item["match"])), None)
        if hit is None:
            missed.append(item["id"])
        else:
            caught.append(item["id"])
            used.add(hit)
    false_positives = [f for i, f in enumerate(found) if i not in used]
    return {"caught": caught, "missed": missed, "false_positives": false_positives}


def expected_bool(question: dict) -> bool:
    # YAML reads a bare `yes` as True, so accept both spellings.
    return str(question["expected"]).lower() in ("yes", "true")


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def score_answers(answers: dict[str, bool | None], answer_key: dict) -> dict:
    """answers: question id -> True/False, or None when the tool couldn't answer."""
    correct, wrong, skipped = [], [], []
    for q in answer_key["reachability_questions"]:
        got = answers.get(q["id"])
        expected = expected_bool(q)
        if got is None:
            skipped.append(q["id"])
        elif got == expected:
            correct.append(q["id"])
        else:
            wrong.append(q["id"])
    return {"correct": correct, "wrong": wrong, "skipped": skipped}


# ---------- CLI ----------

def newest_snapshot() -> Path:
    files = sorted(Path("snapshots/live").glob("*.json"))
    if not files:
        raise SystemExit("No snapshot found. Run collector/collect.py first, or pass --snapshot.")
    return files[-1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Naive rule-based baseline scorecard")
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--answer-key", type=Path, default=Path("answer_key/expected_findings.yaml"))
    parser.add_argument("--out", type=Path, help="Write the scorecard JSON here")
    args = parser.parse_args(argv)

    snap_path = args.snapshot or newest_snapshot()
    snapshot = json.loads(snap_path.read_text())
    key = load_answer_key(args.answer_key)

    found = run_checks(snapshot)
    fscore = score_findings(found, key)

    answers, reasons = {}, {}
    for q in key["reachability_questions"]:
        ok, why = naive_reachable(snapshot, q["source"], q["destination"], q["port"])
        answers[q["id"]], reasons[q["id"]] = ok, why
    qscore = score_answers(answers, key)

    print(f"Snapshot: {snap_path}\n")
    print("Findings")
    for f in found:
        where = f.get("security_group") or f.get("subnet")
        port = f"tcp/{f['port']} " if "port" in f else ""
        print(f"  [{f['severity']:>6}] {f['check']}: {where} {port}- {f['detail']}")
    total = len(key["findings"])
    print(f"\n  Caught {len(fscore['caught'])}/{total}: {', '.join(fscore['caught']) or '-'}")
    print(f"  Missed: {', '.join(fscore['missed']) or 'none'}")
    print(f"  False positives: {len(fscore['false_positives'])}")

    print("\nReachability (naive: security groups + routes, no NACLs)")
    for q in key["reachability_questions"]:
        mark = "ok   " if q["id"] in qscore["correct"] else "WRONG"
        print(f"  {mark} {q['id']} {q['question']} -> {yes_no(answers[q['id']])} "
              f"(expected {yes_no(expected_bool(q))}): {reasons[q['id']]}")
    print(f"\n  Correct {len(qscore['correct'])}/{len(key['reachability_questions'])}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({
            "tool": "naive-baseline",
            "snapshot": str(snap_path),
            "findings": found,
            "finding_score": fscore,
            "answers": {k: {"reachable": v, "reason": reasons[k]} for k, v in answers.items()},
            "answer_score": qscore,
        }, indent=2) + "\n")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
