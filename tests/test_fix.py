"""Offline tests for fix proposals and verification. Uses copies of the real lab
Terraform files, a scripted fake model, and no AWS calls."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for sub in ("auditor", "baseline", "collector", "tests"):
    sys.path.insert(0, str(ROOT / sub))

import propose_fix as pf  # noqa: E402
import verify_fix as vf  # noqa: E402
from lab_snapshot import ANSWER_KEY, lab_snapshot  # noqa: E402

TF = ROOT / "terraform"
P1 = "aws_vpc_security_group_ingress_rule.web_ssh_world"
P3 = "aws_vpc_security_group_ingress_rule.db_mysql_vpc"
P5 = "aws_network_acl.public"


def resources():
    return pf.list_resources(TF)


# ---------- finding and splicing blocks ----------

def test_find_block_includes_its_comment():
    b = pf.find_block(TF, P1)
    assert b["path"].name == "security.tf"
    assert b["text"].startswith("# PLANTED P1")
    assert b["text"].rstrip().endswith("}")
    assert b["file_text"][b["start"]:b["end"]] == b["text"]


def test_find_block_handles_nested_blocks():
    b = pf.find_block(TF, P5)
    assert b["text"].count("ingress {") == 2 and b["text"].count("egress {") == 1
    assert 'tags = { Name = "${var.project}-public-nacl" }' in b["text"]


def test_missing_resource_is_a_clear_error():
    with pytest.raises(SystemExit, match="not found"):
        pf.find_block(TF, "aws_vpc_security_group_ingress_rule.nope")


def test_delete_removes_only_that_block():
    b = pf.find_block(TF, P1)
    new = pf.splice(b, "delete", "")
    assert "web_ssh_world" not in new and "PLANTED P1" not in new
    for other in ("web_rdp_world", "web_http_world", "web_https_world", "db_mysql_vpc"):
        assert other in new
    assert "\n\n\n" not in new
    assert len(new) == len(b["file_text"]) - (b["end"] - b["start"]) - 1


# ---------- guardrails ----------

P3_FIX = '''# FIXED P3: MySQL only from the web tier's security group.
resource "aws_vpc_security_group_ingress_rule" "db_mysql_vpc" {
  security_group_id            = aws_security_group.db.id
  description                  = "MySQL from web tier"
  ip_protocol                  = "tcp"
  from_port                    = 3306
  to_port                      = 3306
  referenced_security_group_id = aws_security_group.web.id
}'''


def p3_block():
    return pf.find_block(TF, P3)["text"]


def test_good_replacement_passes():
    reply = {"action": "replace", "replacement": P3_FIX, "rationale": "Scope to web tier."}
    assert pf.check_proposal(reply, P3, p3_block(), resources()) == []


def test_delete_of_single_rule_is_allowed():
    reply = {"action": "delete", "replacement": "", "rationale": "Use SSM instead of SSH."}
    assert pf.check_proposal(reply, P1, pf.find_block(TF, P1)["text"], resources()) == []


def test_delete_of_whole_nacl_is_refused():
    reply = {"action": "delete", "replacement": "", "rationale": "Remove the NACL."}
    problems = pf.check_proposal(reply, P5, pf.find_block(TF, P5)["text"], resources())
    assert any("more open default" in p for p in problems)


def test_renamed_resource_is_refused():
    reply = {"action": "replace", "rationale": "x",
             "replacement": P3_FIX.replace('"db_mysql_vpc"', '"db_mysql_web"')}
    assert any("must keep resource" in p for p in pf.check_proposal(reply, P3, p3_block(), resources()))


def test_extra_resource_is_refused():
    reply = {"action": "replace", "rationale": "x",
             "replacement": P3_FIX + '\nresource "aws_iam_user" "backdoor" {\n  name = "x"\n}'}
    assert any("exactly one resource" in p for p in pf.check_proposal(reply, P3, p3_block(), resources()))


def test_widening_to_world_is_refused():
    reply = {"action": "replace", "rationale": "x",
             "replacement": P3_FIX.replace("referenced_security_group_id = aws_security_group.web.id",
                                           'cidr_ipv4 = "0.0.0.0/0"')}
    assert any("0.0.0.0/0" in p for p in pf.check_proposal(reply, P3, p3_block(), resources()))


def test_made_up_reference_is_refused():
    reply = {"action": "replace", "rationale": "x",
             "replacement": P3_FIX.replace("aws_security_group.web.id", "aws_security_group.app.id")}
    assert any("aws_security_group.app" in p for p in pf.check_proposal(reply, P3, p3_block(), resources()))


def test_provider_block_is_refused():
    reply = {"action": "replace", "rationale": "x", "replacement": P3_FIX + '\nprovider "aws" {}'}
    problems = pf.check_proposal(reply, P3, p3_block(), resources())
    assert problems  # caught as extra text and as a forbidden top-level block


def test_missing_rationale_and_bad_action():
    assert pf.check_proposal({"action": "nuke"}, P1, "", resources()) == ['"action" must be "delete" or "replace"']
    assert pf.check_proposal(None, P1, "", resources()) == ["the reply was not a single JSON object"]
    assert any("rationale" in p for p in pf.check_proposal({"action": "delete"}, P1, "", resources()))


# ---------- patches apply cleanly with git ----------

def git_apply_check(patch: str) -> subprocess.CompletedProcess:
    tmp = Path(tempfile.mkdtemp())
    try:
        shutil.copytree(TF, tmp / "terraform", ignore=shutil.ignore_patterns(".terraform*"))
        subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
        (tmp / "fix.patch").write_text(patch)
        return subprocess.run(["git", "apply", "--check", "fix.patch"], cwd=tmp, capture_output=True, text=True)
    finally:
        shutil.rmtree(tmp)


def test_delete_patch_applies_with_git():
    if not shutil.which("git"):
        pytest.importorskip("git_not_installed")
    b = pf.find_block(TF, P1)
    patch = pf.make_patch(b, pf.splice(b, "delete", ""), TF)
    assert patch.startswith("--- a/terraform/security.tf\n+++ b/terraform/security.tf\n")
    r = git_apply_check(patch)
    assert r.returncode == 0, r.stderr


def test_replace_patch_applies_with_git():
    if not shutil.which("git"):
        pytest.importorskip("git_not_installed")
    b = pf.find_block(TF, P3)
    patch = pf.make_patch(b, pf.splice(b, "replace", P3_FIX), TF)
    assert "+  referenced_security_group_id = aws_security_group.web.id" in patch
    r = git_apply_check(patch)
    assert r.returncode == 0, r.stderr


def test_validate_skips_when_terraform_is_not_initialized():
    status, msg = pf.terraform_validate(Path(tempfile.mkdtemp()), "security.tf", "")
    assert status == "skipped" and "terraform plan" in msg


# ---------- model loop ----------

class FakeBedrock:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def converse(self, **kw):
        self.requests.append(json.loads(json.dumps(kw)))
        text = self.replies.pop(0)
        return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}},
                "usage": {"inputTokens": 400, "outputTokens": 80}}


def test_model_retry_fixes_a_rejected_proposal():
    bad = json.dumps({"action": "delete", "replacement": "", "rationale": "Remove NACL"})
    good = json.dumps({"action": "replace", "replacement": P3_FIX, "rationale": "Scope to web tier."})
    bedrock = FakeBedrock([bad.replace("Remove NACL", ""), good])
    reply, problems, usage = pf.ask_model(bedrock, "m", {"x": 1}, P3, p3_block(), resources())
    assert problems == [] and reply["action"] == "replace"
    assert "rejected" in bedrock.requests[1]["messages"][-1]["content"][0]["text"]
    assert usage == {"inputTokens": 800, "outputTokens": 160}
    assert "toolConfig" not in bedrock.requests[0]  # proposals get no tools at all


def test_model_gives_up_after_two_bad_proposals():
    bad = json.dumps({"action": "replace", "replacement": "nope", "rationale": "x"})
    reply, problems, _ = pf.ask_model(FakeBedrock([bad, bad]), "m", {}, P3, p3_block(), resources())
    assert problems and "exactly one resource block" in problems[0]


def test_system_prompt_prefers_removal_and_no_personal_ip():
    assert "Session Manager" in pf.SYSTEM_PROMPT and "personal" in pf.SYSTEM_PROMPT


# ---------- verification logic ----------

def fixed_p1_snapshot():
    snap = lab_snapshot()
    web = next(g for g in snap["security_groups"] if g["name"] == "network-auditor-web-sg")
    web["ingress"] = [r for r in web["ingress"] if r["from_port"] != 22]
    return snap


P1_RECORD = {"finding_id": "P1", "baseline_caught_before": True,
             "verify": {"source": "internet", "destination": "web", "port": 22, "after": "blocked"}}


def blocked(spec):
    return {"reachable": False, "blocked_by": "ENI_SG_RULES_MISMATCH at network-auditor-web-sg"}


def reachable(spec):
    return {"reachable": True, "blocked_by": None}


def test_verify_passes_when_rule_gone_and_path_blocked():
    r = vf.evaluate(P1_RECORD, fixed_p1_snapshot(), ANSWER_KEY, blocked)
    assert r["passed"] and r["rule_level"]["passed"] and r["path_level"]["passed"]


def test_verify_fails_when_path_still_reachable():
    r = vf.evaluate(P1_RECORD, fixed_p1_snapshot(), ANSWER_KEY, reachable)
    assert not r["passed"] and not r["path_level"]["passed"]


def test_verify_fails_when_baseline_still_finds_it():
    r = vf.evaluate(P1_RECORD, lab_snapshot(), ANSWER_KEY, blocked)
    assert not r["passed"] and not r["rule_level"]["passed"]


def test_p3_fix_must_keep_web_to_db_working():
    record = {"finding_id": "P3", "baseline_caught_before": True,
              "verify": {"source": "web", "destination": "db", "port": 3306, "after": "reachable"}}
    snap = lab_snapshot()
    db = next(g for g in snap["security_groups"] if g["name"] == "network-auditor-db-sg")
    db["ingress"] = [{"protocol": "tcp", "from_port": 3306, "to_port": 3306,
                      "source_type": "security_group", "source": "sg-web", "description": None}]
    assert vf.evaluate(record, snap, ANSWER_KEY, reachable)["passed"]
    assert not vf.evaluate(record, snap, ANSWER_KEY, blocked)["passed"]  # over-fixed: broke the app


def test_p4_is_verified_by_baseline_alone():
    record = {"finding_id": "P4", "baseline_caught_before": True, "verify": None}
    snap = lab_snapshot()
    rt = next(r for r in snap["route_tables"] if r["name"] == "network-auditor-private-rt")
    rt["routes"] = [r for r in rt["routes"] if r["target_type"] == "local"]
    r = vf.evaluate(record, snap, ANSWER_KEY, lambda s: pytest.fail("analyzer should not run"))
    assert r["passed"] and r["path_level"] is None
