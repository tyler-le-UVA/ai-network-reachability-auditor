"""Offline tests for the naive baseline and the Reachability Analyzer wrapper."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "baseline"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import checks  # noqa: E402
import reachability  # noqa: E402
from lab_snapshot import ANSWER_KEY, lab_snapshot  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


# ---------- checks ----------

def test_baseline_catches_p1_to_p4_and_misses_p5():
    score = checks.score_findings(checks.run_checks(lab_snapshot()), ANSWER_KEY)
    assert score["caught"] == ["P1", "P2", "P3", "P4"]
    assert score["missed"] == ["P5"]  # by design: the naive baseline ignores NACLs
    assert score["false_positives"] == []


def test_https_control_is_not_flagged():
    found = checks.run_checks(lab_snapshot())
    assert not any(f.get("port") in (80, 443) for f in found)


def test_all_traffic_rule_is_flagged_once():
    snap = lab_snapshot()
    snap["security_groups"][2]["ingress"] = [{"protocol": "all", "from_port": None, "to_port": None,
                                              "source_type": "cidr", "source": "0.0.0.0/0", "description": None}]
    found = checks.check_world_open(snap)
    assert [f["check"] for f in found] == ["all_traffic_open_to_world"]


def test_port_range_covering_ssh_is_flagged():
    snap = lab_snapshot()
    snap["security_groups"][2]["ingress"] = [{"protocol": "tcp", "from_port": 20, "to_port": 25,
                                              "source_type": "cidr", "source": "0.0.0.0/0", "description": None}]
    ports = sorted(f["port"] for f in checks.check_world_open(snap))
    assert ports == [21, 22, 23]


def test_db_rule_from_security_group_or_single_host_is_fine():
    snap = lab_snapshot()
    snap["security_groups"][1]["ingress"] = [
        {"protocol": "tcp", "from_port": 3306, "to_port": 3306, "source_type": "security_group",
         "source": "sg-web", "description": None},
        {"protocol": "tcp", "from_port": 3306, "to_port": 3306, "source_type": "cidr",
         "source": "10.20.1.42/32", "description": None},
    ]
    assert checks.check_db_port_from_cidr(snap) == []


def test_fixed_private_route_table_is_not_flagged():
    snap = lab_snapshot()
    snap["route_tables"][1]["routes"] = snap["route_tables"][1]["routes"][:1]  # local only
    assert checks.check_private_subnet_igw(snap) == []


# ---------- naive reachability ----------

def naive_answers(snap):
    return {q["id"]: checks.naive_reachable(snap, q["source"], q["destination"], q["port"])[0]
            for q in ANSWER_KEY["reachability_questions"]}


def test_naive_reachability_gets_everything_but_the_nacl_question():
    score = checks.score_answers(naive_answers(lab_snapshot()), ANSWER_KEY)
    assert score["wrong"] == ["Q3"]  # says port 80 is open; the NACL actually blocks it
    assert len(score["correct"]) == 6


def test_web_to_db_allowed_by_security_group_reference():
    snap = lab_snapshot()
    snap["security_groups"][1]["ingress"] = [{"protocol": "tcp", "from_port": 3306, "to_port": 3306,
                                              "source_type": "security_group", "source": "sg-web",
                                              "description": None}]
    assert checks.naive_reachable(snap, "web", "db", 3306)[0] is True
    assert checks.naive_reachable(snap, "vpc", "db", 3306)[0] is False  # the P3 fix


def test_score_answers_marks_skipped():
    score = checks.score_answers({"Q1": True}, ANSWER_KEY)
    assert score["correct"] == ["Q1"]
    assert "Q7" in score["skipped"]


def test_real_answer_key_has_match_fields():
    pytest.importorskip("yaml")
    key = checks.load_answer_key(REPO / "answer_key" / "expected_findings.yaml")
    assert [f["id"] for f in key["findings"]] == ["P1", "P2", "P3", "P4", "P5"]
    assert all("match" in f for f in key["findings"])
    assert all({"source", "destination", "port"} <= q.keys() for q in key["reachability_questions"])
    # The inline copy used by the other tests must stay in sync with the real file.
    assert [f["match"] for f in key["findings"]] == [f["match"] for f in ANSWER_KEY["findings"]]


# ---------- Reachability Analyzer wrapper ----------

class FakeEC2:
    """Just enough of the EC2 client for check_path. Records every call."""

    def __init__(self, analyses, fail_start=False):
        self.analyses = list(analyses)  # successive describe responses
        self.fail_start = fail_start
        self.calls = []

    def create_network_insights_path(self, **kw):
        self.calls.append(("create_path", kw))
        return {"NetworkInsightsPath": {"NetworkInsightsPathId": "nip-1"}}

    def start_network_insights_analysis(self, **kw):
        self.calls.append(("start", kw))
        if self.fail_start:
            raise RuntimeError("boom")
        return {"NetworkInsightsAnalysis": {"NetworkInsightsAnalysisId": "nia-1"}}

    def describe_network_insights_analyses(self, **kw):
        self.calls.append(("describe", kw))
        return {"NetworkInsightsAnalyses": [self.analyses.pop(0) if len(self.analyses) > 1 else self.analyses[0]]}

    def delete_network_insights_analysis(self, **kw):
        self.calls.append(("delete_analysis", kw))

    def delete_network_insights_path(self, **kw):
        self.calls.append(("delete_path", kw))

    def names(self):
        return [c[0] for c in self.calls]


NACL_BLOCK = {
    "Status": "succeeded",
    "NetworkPathFound": False,
    "Explanations": [{
        "ExplanationCode": "ENI_ACL_RULES_MISMATCH",
        "Acl": {"Id": "acl-public", "Name": "network-auditor-public-nacl"},
        "AclRule": {"RuleNumber": 90, "RuleAction": "deny", "Protocol": "6",
                    "PortRange": {"From": 80, "To": 80}, "Cidr": "0.0.0.0/0", "Egress": False},
    }],
}


def test_reachable_path():
    ec2 = FakeEC2([{"Status": "succeeded", "NetworkPathFound": True,
                    "ForwardPathComponents": [{"Component": {"Id": "igw-lab"}},
                                              {"Component": {"Id": "i-web"}}]}])
    r = reachability.check_path(ec2, "igw-lab", "i-web", 22, sleep=lambda s: None)
    assert r["reachable"] is True and r["blocked_by"] is None
    assert r["path_components"] == ["igw-lab", "i-web"]
    create = ec2.calls[0][1]
    assert create == {"Source": "igw-lab", "Destination": "i-web", "Protocol": "tcp", "DestinationPort": 22}


def test_blocked_by_nacl_names_the_rule():
    ec2 = FakeEC2([NACL_BLOCK])
    r = reachability.check_path(ec2, "igw-lab", "i-web", 80, sleep=lambda s: None)
    assert r["reachable"] is False
    assert r["explanations"][0]["acl_rule"]["rule_number"] == 90
    assert "network-auditor-public-nacl" in r["blocked_by"] and "rule 90 deny" in r["blocked_by"]


def test_polls_until_done_and_cleans_up():
    ec2 = FakeEC2([{"Status": "running"}, {"Status": "running"}, NACL_BLOCK])
    reachability.check_path(ec2, "igw-lab", "i-web", 80, sleep=lambda s: None)
    assert ec2.names().count("describe") == 3
    assert ec2.names()[-2:] == ["delete_analysis", "delete_path"]


def test_cleans_up_path_even_when_start_fails():
    ec2 = FakeEC2([NACL_BLOCK], fail_start=True)
    with pytest.raises(RuntimeError):
        reachability.check_path(ec2, "igw-lab", "i-web", 80, sleep=lambda s: None)
    assert ec2.names()[-1] == "delete_path"
    assert "delete_analysis" not in ec2.names()


def test_timeout_raises_and_cleans_up():
    ec2 = FakeEC2([{"Status": "running"}])
    with pytest.raises(TimeoutError):
        reachability.check_path(ec2, "igw-lab", "i-web", 80, timeout=6, poll=3, sleep=lambda s: None)
    assert ec2.names()[-2:] == ["delete_analysis", "delete_path"]


def test_failed_analysis_raises():
    ec2 = FakeEC2([{"Status": "failed", "StatusMessage": "permission denied"}])
    with pytest.raises(RuntimeError, match="permission denied"):
        reachability.check_path(ec2, "igw-lab", "i-web", 80, sleep=lambda s: None)


def test_resolve_roles():
    snap = lab_snapshot()
    assert reachability.resolve(snap, "internet") == "igw-lab"
    assert reachability.resolve(snap, "web") == "i-web"
    assert reachability.resolve(snap, "vpc") is None
