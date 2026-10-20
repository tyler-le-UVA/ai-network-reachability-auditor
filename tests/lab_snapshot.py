"""A hand-built snapshot in the collector's schema that mirrors the Milestone 1 lab.
Used by the baseline tests so they run with no AWS account and no moto."""

import copy

_LAB = {
    "schema_version": 1,
    "collected_at": "2026-10-20T19:04:42+00:00",
    "region": "us-east-1",
    "vpc": {"id": "vpc-lab", "name": "network-auditor-vpc", "cidr": "10.20.0.0/16"},
    "internet_gateways": [{"id": "igw-lab", "name": "network-auditor-igw"}],
    "subnets": [
        {"id": "subnet-public", "name": "network-auditor-public", "cidr": "10.20.1.0/24",
         "availability_zone": "us-east-1a", "map_public_ip_on_launch": True,
         "route_table_id": "rtb-public", "route_table_explicit": True, "network_acl_id": "acl-public"},
        {"id": "subnet-private", "name": "network-auditor-private", "cidr": "10.20.2.0/24",
         "availability_zone": "us-east-1a", "map_public_ip_on_launch": False,
         "route_table_id": "rtb-private", "route_table_explicit": True, "network_acl_id": "acl-default"},
    ],
    "route_tables": [
        {"id": "rtb-main", "name": None, "main": True, "subnet_ids": [],
         "routes": [{"destination": "10.20.0.0/16", "target_type": "local", "target_id": "local", "state": "active"}]},
        {"id": "rtb-private", "name": "network-auditor-private-rt", "main": False, "subnet_ids": ["subnet-private"],
         "routes": [
             {"destination": "10.20.0.0/16", "target_type": "local", "target_id": "local", "state": "active"},
             {"destination": "0.0.0.0/0", "target_type": "internet_gateway", "target_id": "igw-lab", "state": "active"},
         ]},
        {"id": "rtb-public", "name": "network-auditor-public-rt", "main": False, "subnet_ids": ["subnet-public"],
         "routes": [
             {"destination": "10.20.0.0/16", "target_type": "local", "target_id": "local", "state": "active"},
             {"destination": "0.0.0.0/0", "target_type": "internet_gateway", "target_id": "igw-lab", "state": "active"},
         ]},
    ],
    "network_acls": [
        {"id": "acl-default", "name": None, "default": True, "subnet_ids": ["subnet-private"],
         "ingress": [
             {"rule_no": 100, "action": "allow", "protocol": "all", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"},
             {"rule_no": 32767, "action": "deny", "protocol": "all", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"},
         ],
         "egress": []},
        {"id": "acl-public", "name": "network-auditor-public-nacl", "default": False, "subnet_ids": ["subnet-public"],
         "ingress": [
             {"rule_no": 90, "action": "deny", "protocol": "tcp", "from_port": 80, "to_port": 80, "cidr": "0.0.0.0/0"},
             {"rule_no": 100, "action": "allow", "protocol": "all", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"},
             {"rule_no": 32767, "action": "deny", "protocol": "all", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"},
         ],
         "egress": []},
    ],
    "security_groups": [
        {"id": "sg-default", "name": "default", "description": "default VPC security group",
         "ingress": [{"protocol": "all", "from_port": None, "to_port": None,
                      "source_type": "security_group", "source": "sg-default", "description": None}],
         "egress": []},
        {"id": "sg-db", "name": "network-auditor-db-sg", "description": "Database tier",
         "ingress": [{"protocol": "tcp", "from_port": 3306, "to_port": 3306,
                      "source_type": "cidr", "source": "10.20.0.0/16", "description": "MySQL from VPC"}],
         "egress": []},
        {"id": "sg-web", "name": "network-auditor-web-sg", "description": "Web tier",
         "ingress": [
             {"protocol": "tcp", "from_port": p, "to_port": p, "source_type": "cidr", "source": "0.0.0.0/0",
              "description": d}
             for p, d in [(22, "SSH from anywhere"), (80, "HTTP from anywhere"),
                          (443, "HTTPS from anywhere"), (3389, "RDP from anywhere")]
         ],
         "egress": []},
    ],
    "instances": [
        {"id": "i-db", "name": "network-auditor-db", "role": "db", "state": "running",
         "subnet_id": "subnet-private", "private_ip": "10.20.2.219", "public_ip": None,
         "security_group_ids": ["sg-db"], "imdsv2_required": True},
        {"id": "i-web", "name": "network-auditor-web", "role": "web", "state": "running",
         "subnet_id": "subnet-public", "private_ip": "10.20.1.42", "public_ip": "3.210.200.186",
         "security_group_ids": ["sg-web"], "imdsv2_required": True},
    ],
}

# Mirrors answer_key/expected_findings.yaml so most tests don't need PyYAML.
ANSWER_KEY = {
    "findings": [
        {"id": "P1", "match": {"check": "sensitive_port_open_to_world", "security_group": "network-auditor-web-sg", "port": 22}},
        {"id": "P2", "match": {"check": "sensitive_port_open_to_world", "security_group": "network-auditor-web-sg", "port": 3389}},
        {"id": "P3", "match": {"check": "db_port_from_cidr", "security_group": "network-auditor-db-sg", "port": 3306}},
        {"id": "P4", "match": {"check": "private_subnet_routes_to_igw", "subnet": "network-auditor-private"}},
        {"id": "P5", "match": {"check": "nacl_blocks_sg_allowed_port", "network_acl": "network-auditor-public-nacl", "port": 80}},
    ],
    "reachability_questions": [
        {"id": "Q1", "question": "internet -> web 22", "source": "internet", "destination": "web", "port": 22, "expected": "yes"},
        {"id": "Q2", "question": "internet -> web 3389", "source": "internet", "destination": "web", "port": 3389, "expected": "yes"},
        {"id": "Q3", "question": "internet -> web 80", "source": "internet", "destination": "web", "port": 80, "expected": "no"},
        {"id": "Q4", "question": "internet -> web 443", "source": "internet", "destination": "web", "port": 443, "expected": "yes"},
        {"id": "Q5", "question": "internet -> db 3306", "source": "internet", "destination": "db", "port": 3306, "expected": "no"},
        {"id": "Q6", "question": "web -> db 3306", "source": "web", "destination": "db", "port": 3306, "expected": "yes"},
        {"id": "Q7", "question": "vpc -> db 3306", "source": "vpc", "destination": "db", "port": 3306, "expected": "yes"},
    ],
}


def lab_snapshot() -> dict:
    return copy.deepcopy(_LAB)
