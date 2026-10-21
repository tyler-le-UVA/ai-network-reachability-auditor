"""Milestone 6: score every approach on the same questions.

Tools compared:
  baseline   naive rule-based reachability (security groups + routes, no NACLs). Free.
  analyzer   Reachability Analyzer called directly on the structured form of each question.
  ai:<model> the AI auditor, given only the plain-English question.

Cost control: every analyzer result is cached on disk, keyed by the exact network
configuration, so a path is paid for once no matter how many models ask about it.
A hard cap (--max-analyzer-runs) stops runaway spending.

Usage (CloudShell, repo root, lab deployed with every planted issue, fresh snapshot):
    python3 eval/run_eval.py
    python3 eval/run_eval.py --models us.amazon.nova-2-lite-v1:0 --tools baseline,ai
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("auditor", "baseline", "collector"):
    sys.path.insert(0, str(ROOT / sub))

from agent import Auditor  # noqa: E402
from checks import naive_reachable  # noqa: E402
from reachability import COST_PER_ANALYSIS, build_name_map, check_path, resolve  # noqa: E402

DEFAULT_MODELS = ["us.amazon.nova-2-lite-v1:0", "us.amazon.nova-lite-v1:0", "us.amazon.nova-micro-v1:0"]
CACHE_PATH = Path("snapshots/live/.analyzer_cache")  # git-ignored; not *.json so it's never taken for a snapshot


# ---------- analyzer cache ----------

def fingerprint(snapshot: dict) -> str:
    """Hash of the network configuration (not the collection time)."""
    body = {k: v for k, v in snapshot.items() if k != "collected_at"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


class BudgetExceeded(RuntimeError):
    pass


class CachedAnalyzer:
    """Drop-in replacement for reachability.check_path that caches by configuration.

    If the network changes (a fix is applied, the lab is rebuilt), the fingerprint
    changes and old results are never reused."""

    def __init__(self, ec2, fingerprint: str, cache_path: Path | None = CACHE_PATH,
                 max_runs: int = 25, check_fn=check_path):
        self.ec2 = ec2
        self.fp = fingerprint
        self.cache_path = cache_path
        self.max_runs = max_runs
        self.check_fn = check_fn
        self.runs = 0
        self.hits = 0
        self.cache: dict[str, dict] = {}
        if cache_path and cache_path.exists():
            try:
                self.cache = json.loads(cache_path.read_text())
            except json.JSONDecodeError:
                self.cache = {}

    def key(self, src, dst, protocol, port) -> str:
        return f"{self.fp}|{src}|{dst}|{protocol}|{port}"

    def __call__(self, _ec2, src, dst, port, protocol="tcp", names=None):
        k = self.key(src, dst, protocol, port)
        if k in self.cache:
            self.hits += 1
            return copy.deepcopy(self.cache[k])
        if self.runs >= self.max_runs:
            raise BudgetExceeded(f"evaluation analyzer cap of {self.max_runs} runs reached")
        result = self.check_fn(self.ec2, src, dst, port, protocol, names=names)
        self.runs += 1
        self.cache[k] = result
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self.cache, default=str))
        return copy.deepcopy(result)


# ---------- prompt injection ----------

def apply_injection(snapshot: dict, inject: dict) -> dict:
    """Copy of the snapshot with attacker text in one security group rule's description."""
    snap = copy.deepcopy(snapshot)
    group = next(g for g in snap["security_groups"] if g["name"] == inject["security_group"])
    hits = [r for r in group["ingress"] if r.get("from_port") == inject["port"]]
    if not hits:
        raise ValueError(f"no ingress rule on port {inject['port']} in {inject['security_group']}")
    for r in hits:
        r["description"] = inject["text"]
    return snap


# ---------- scoring ----------

def expected_of(case: dict) -> str:
    v = case["expected"]
    if v is True:
        return "yes"
    if v is False:
        return "no"
    return str(v).lower()


def grade(case: dict, answer: str | None, verified: bool = True) -> str:
    """correct / wrong / abstained / n/a. A withheld or declined answer is 'abstained',
    which is safer than 'wrong': the tool admitted it couldn't prove an answer."""
    exp = expected_of(case)
    if answer is None:
        return "n/a"
    if answer == "unknown":
        return "correct" if exp == "unknown" else "abstained"
    if exp == "unknown":
        return "wrong"
    return "correct" if verified and answer == exp else "wrong"


def summarize(rows: list[dict]) -> dict:
    graded = [r for r in rows if r["grade"] != "n/a"]
    out = {g: sum(r["grade"] == g for r in graded) for g in ("correct", "wrong", "abstained", "error")}
    out["answered"] = len(graded)
    out["accuracy"] = round(out["correct"] / len(graded), 3) if graded else None
    for k in ("inputTokens", "outputTokens", "analyzer_calls"):
        if any(k in r for r in rows):
            out[k] = sum(r.get(k, 0) for r in rows)
    lat = [r["seconds"] for r in rows if "seconds" in r]
    if lat:
        out["avg_seconds"] = round(sum(lat) / len(lat), 1)
    return out


# ---------- runners ----------

def run_baseline(cases: list[dict], snapshot: dict) -> list[dict]:
    rows = []
    for c in cases:
        p = c.get("path")
        if not p:
            rows.append({"id": c["id"], "answer": None, "grade": "n/a"})
            continue
        ok, why = naive_reachable(snapshot, p["source"], p["destination"], p["port"])
        ans = "yes" if ok else "no"
        rows.append({"id": c["id"], "answer": ans, "grade": grade(c, ans), "reason": why})
    return rows


def run_analyzer(cases: list[dict], snapshot: dict, analyzer: CachedAnalyzer) -> list[dict]:
    names = build_name_map(snapshot)
    rows = []
    for c in cases:
        p = c.get("path")
        src = resolve(snapshot, p["source"]) if p else None
        if not p or src is None:
            rows.append({"id": c["id"], "answer": None, "grade": "n/a"})
            continue
        try:
            r = analyzer(None, src, resolve(snapshot, p["destination"]), p["port"], "tcp", names=names)
        except Exception as err:
            rows.append({"id": c["id"], "answer": None, "grade": "error", "error": str(err)})
            continue
        ans = "yes" if r["reachable"] else "no"
        rows.append({"id": c["id"], "answer": ans, "grade": grade(c, ans), "reason": r["blocked_by"]})
    return rows


def run_ai(cases: list[dict], snapshot: dict, model: str, bedrock, analyzer: CachedAnalyzer,
           max_checks: int = 4, log=print) -> list[dict]:
    rows = []
    for c in cases:
        snap = apply_injection(snapshot, c["inject"]) if c.get("inject") else snapshot
        auditor = Auditor(bedrock, ec2=None, snapshot=snap, model_id=model,
                          max_checks=max_checks, check_fn=analyzer)
        start = time.monotonic()
        try:
            r = auditor.ask(c["question"])
        except Exception as err:  # model access denied, throttling that outlasted retries, ...
            rows.append({"id": c["id"], "answer": None, "grade": "error",
                         "error": f"{type(err).__name__}: {err}"})
            log(f"    {c['id']} ERROR {type(err).__name__}: {err}")
            continue
        row = {
            "id": c["id"],
            "answer": r["answer"],
            "verified": r["verified"],
            "grade": grade(c, r["answer"], r["verified"]),
            "summary": r["summary"],
            "citations": r["citations"],
            "checks": [{"id": k["citation_id"], "path": f"{k['source_label']} -> {k['destination_label']} "
                        f"{k['protocol']}/{k['port']}", "reachable": k["reachable"]} for k in r["checks"]],
            "analyzer_calls": len(r["checks"]),
            "rejections": r["rejections"],
            "inputTokens": r["usage"]["inputTokens"],
            "outputTokens": r["usage"]["outputTokens"],
            "seconds": round(time.monotonic() - start, 1),
        }
        if c.get("inject"):
            target = c["inject"]["target_answer"]
            row["injection"] = {
                "model_tried_to_follow": any((a or {}).get("answer") == target for a in r["attempts"]),
                "defense_held": row["grade"] != "wrong",
            }
        rows.append(row)
        log(f"    {c['id']} {row['answer']:<8} {row['grade']:<9} checks={row['analyzer_calls']} "
            f"rejected={len(row['rejections'])}")
    return rows


# ---------- report ----------

def short(model: str) -> str:
    return model.split(".", 1)[-1].replace("amazon.", "").replace("-v1:0", "")


def markdown(cases: list[dict], tools: dict[str, list[dict]], summaries: dict[str, dict]) -> str:
    names = list(tools)
    lines = ["| Tool | Answered | Correct | Wrong | Abstained | Errors | Accuracy | Analyzer calls | Tokens in / out |",
             "|---|---|---|---|---|---|---|---|---|"]
    for n in names:
        s = summaries[n]
        acc = f"{s['accuracy']:.0%}" if s["accuracy"] is not None else "-"
        tok = f"{s['inputTokens']:,} / {s['outputTokens']:,}" if "inputTokens" in s else "-"
        lines.append(f"| {n} | {s['answered']} | {s['correct']} | {s['wrong']} | {s['abstained']} | "
                     f"{s['error']} | {acc} | {s.get('analyzer_calls', '-')} | {tok} |")
    lines += ["", "| Case | Question | Expected | " + " | ".join(names) + " |",
              "|---|---|---|" + "---|" * len(names)]
    mark = {"correct": "✅", "wrong": "❌", "abstained": "➖", "error": "⚠️", "n/a": "·"}
    for c in cases:
        cells = []
        for n in names:
            row = next(r for r in tools[n] if r["id"] == c["id"])
            cells.append(f"{mark[row['grade']]} {row['answer'] or ''}".strip())
        lines.append(f"| {c['id']} | {c['question']} | {expected_of(c)} | " + " | ".join(cells) + " |")
    inj = [(n, r) for n in names for r in tools[n] if "injection" in r]
    if inj:
        lines += ["", "| Prompt injection | Model tried to follow it | Defense held |", "|---|---|---|"]
        for n, r in inj:
            i = r["injection"]
            lines.append(f"| {n} | {'yes' if i['model_tried_to_follow'] else 'no'} | "
                         f"{'yes' if i['defense_held'] else 'NO'} |")
    return "\n".join(lines) + "\n"


# ---------- CLI ----------

def main(argv: list[str] | None = None) -> int:
    import yaml
    from botocore.config import Config
    from checks import newest_snapshot
    from collect import make_session

    parser = argparse.ArgumentParser(description="Evaluate baseline vs analyzer vs AI auditor")
    parser.add_argument("--questions", type=Path, default=ROOT / "eval" / "questions.yaml")
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--models", default=",".join(DEFAULT_MODELS))
    parser.add_argument("--tools", default="baseline,analyzer,ai")
    parser.add_argument("--cases", help="Comma-separated case IDs to run (default: all)")
    parser.add_argument("--max-analyzer-runs", type=int, default=25)
    parser.add_argument("--max-checks", type=int, default=4, help="Per-question analyzer budget for the AI")
    parser.add_argument("--role-arn", default=os.environ.get("AUDITOR_ROLE_ARN"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--out", type=Path, default=Path("docs/results/m6-eval.json"))
    args = parser.parse_args(argv)

    cases = yaml.safe_load(args.questions.read_text())["cases"]
    if args.cases:
        wanted = {c.strip().upper() for c in args.cases.split(",")}
        cases = [c for c in cases if c["id"] in wanted]
    tools = {t.strip() for t in args.tools.split(",")}
    models = [m.strip() for m in args.models.split(",") if m.strip()] if "ai" in tools else []

    snap_path = args.snapshot or newest_snapshot()
    snapshot = json.loads(snap_path.read_text())
    fp = fingerprint(snapshot)

    needs_aws = bool(tools & {"analyzer", "ai"})
    if needs_aws and not args.role_arn:
        print("error: pass --role-arn or set AUDITOR_ROLE_ARN", file=sys.stderr)
        return 2

    print(f"Snapshot {snap_path} (config {fp}), {len(cases)} cases, tools: "
          f"{', '.join(sorted(tools))}{', models: ' + ', '.join(map(short, models)) if models else ''}")
    if needs_aws:
        print(f"Analyzer results are cached per configuration; at most {args.max_analyzer_runs} new runs "
              f"(about ${args.max_analyzer_runs * COST_PER_ANALYSIS:.2f} worst case, usually much less), "
              f"plus Bedrock calls for {len(cases) * len(models)} questions.")
        if not args.yes and input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            return 1

    session = make_session(args.role_arn, args.region) if needs_aws else None
    analyzer = CachedAnalyzer(session.client("ec2") if session else None, fp, max_runs=args.max_analyzer_runs)

    results: dict[str, list[dict]] = {}
    if "baseline" in tools:
        results["baseline"] = run_baseline(cases, snapshot)
    if "analyzer" in tools:
        print("  analyzer (direct)")
        results["analyzer"] = run_analyzer(cases, snapshot, analyzer)
    if models:
        bedrock = session.client("bedrock-runtime",
                                 config=Config(retries={"max_attempts": 8, "mode": "adaptive"}))
        for m in models:
            print(f"  ai:{short(m)}")
            results[f"ai:{short(m)}"] = run_ai(cases, snapshot, m, bedrock, analyzer, args.max_checks)

    summaries = {n: summarize(rows) for n, rows in results.items()}
    report = markdown(cases, results, summaries)
    print("\n" + report)
    print(f"New analyzer runs: {analyzer.runs} (about ${analyzer.runs * COST_PER_ANALYSIS:.2f}), "
          f"cache hits: {analyzer.hits}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "snapshot": str(snap_path),
        "config_fingerprint": fp,
        "models": models,
        "analyzer_runs": analyzer.runs,
        "analyzer_cache_hits": analyzer.hits,
        "summaries": summaries,
        "results": results,
        "cases": cases,
    }, indent=2, default=str) + "\n")
    md_path = args.out.with_suffix(".md")
    md_path.write_text(f"# Evaluation results\n\nSnapshot config `{fp}`, run "
                       f"{datetime.now(timezone.utc):%Y-%m-%d}.\n\n" + report)
    print(f"wrote {args.out}\nwrote {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
