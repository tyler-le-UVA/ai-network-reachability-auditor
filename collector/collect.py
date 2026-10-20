"""Collect a VPC's network configuration and normalize it to JSON.

Usage (CloudShell, from the repo root):
    python3 collector/collect.py --role-arn "$(terraform -chdir=terraform output -raw auditor_role_arn)"

By default it finds the lab VPC by its Project tag. Output goes to snapshots/live/.
The normalized shape is what later milestones (baseline checks, AI tools) read,
so it keeps only fields that matter for reachability and drops volatile noise.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3

PROTOCOLS = {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}


# ---------- session ----------

def make_session(role_arn: str | None, region: str) -> boto3.Session:
    """Return a session, assuming the read-only auditor role when one is given."""
    if not role_arn:
        return boto3.Session(region_name=region)
    creds = boto3.client("sts", region_name=region).assume_role(
        RoleArn=role_arn, RoleSessionName="network-auditor-collector"
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


# ---------- small helpers ----------

def tag(resource: dict, key: str) -> str | None:
    for t in resource.get("Tags", []) or []:
        if t["Key"] == key:
            return t["Value"]
    return None


def proto(value: str) -> str:
    return PROTOCOLS.get(str(value), str(value))


def paginate(client, method: str, key: str, **kwargs) -> list[dict]:
    items: list[dict] = []
    for page in client.get_paginator(method).paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def vpc_filter(vpc_id: str) -> list[dict]:
    return [{"Name": "vpc-id", "Values": [vpc_id]}]


# ---------- normalizers ----------

def normalize_route(route: dict) -> dict:
    destination = (
        route.get("DestinationCidrBlock")
        or route.get("DestinationIpv6CidrBlock")
        or route.get("DestinationPrefixListId")
    )
    target_type, target_id = "unknown", None
    for key, kind in [
        ("GatewayId", "gateway"),
        ("NatGatewayId", "nat_gateway"),
        ("TransitGatewayId", "transit_gateway"),
        ("VpcPeeringConnectionId", "vpc_peering"),
        ("NetworkInterfaceId", "network_interface"),
        ("InstanceId", "instance"),
        ("EgressOnlyInternetGatewayId", "egress_only_igw"),
    ]:
        if route.get(key):
            target_id = route[key]
            target_type = kind
            break
    if target_type == "gateway":
        if target_id == "local":
            target_type = "local"
        elif target_id.startswith("igw-"):
            target_type = "internet_gateway"
        elif target_id.startswith("vgw-"):
            target_type = "vpn_gateway"
    return {
        "destination": destination,
        "target_type": target_type,
        "target_id": target_id,
        "state": route.get("State", "active"),
    }


def normalize_nacl_entry(entry: dict) -> dict:
    ports = entry.get("PortRange") or {}
    return {
        "rule_no": entry["RuleNumber"],
        "action": entry["RuleAction"],
        "protocol": proto(entry["Protocol"]),
        "from_port": ports.get("From"),
        "to_port": ports.get("To"),
        "cidr": entry.get("CidrBlock") or entry.get("Ipv6CidrBlock"),
    }


def flatten_permissions(permissions: list[dict]) -> list[dict]:
    """Turn AWS IpPermissions into one flat rule per source."""
    rules = []
    for perm in permissions:
        base = {
            "protocol": proto(perm["IpProtocol"]),
            "from_port": perm.get("FromPort"),
            "to_port": perm.get("ToPort"),
        }
        if base["protocol"] == "all":
            base["from_port"] = base["to_port"] = None
        sources = (
            [("cidr", r["CidrIp"], r.get("Description")) for r in perm.get("IpRanges", [])]
            + [("cidr", r["CidrIpv6"], r.get("Description")) for r in perm.get("Ipv6Ranges", [])]
            + [("security_group", g["GroupId"], g.get("Description")) for g in perm.get("UserIdGroupPairs", [])]
            + [("prefix_list", p["PrefixListId"], p.get("Description")) for p in perm.get("PrefixListIds", [])]
        )
        for source_type, source, description in sources:
            rules.append({**base, "source_type": source_type, "source": source, "description": description})
    return sorted(rules, key=lambda r: (r["from_port"] if r["from_port"] is not None else -1, r["source"]))


# ---------- collection ----------

def find_vpc(ec2, vpc_id: str | None, project: str) -> dict:
    if vpc_id:
        vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    else:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Project", "Values": [project]}])["Vpcs"]
    if len(vpcs) != 1:
        raise SystemExit(
            f"Expected exactly one VPC, found {len(vpcs)}. "
            "Is the lab deployed? Pass --vpc-id to pick one explicitly."
        )
    return vpcs[0]


def collect(session: boto3.Session, vpc_id: str | None = None, project: str = "network-auditor") -> dict:
    ec2 = session.client("ec2")
    vpc = find_vpc(ec2, vpc_id, project)
    vid = vpc["VpcId"]
    f = vpc_filter(vid)

    igws = paginate(
        ec2, "describe_internet_gateways", "InternetGateways",
        Filters=[{"Name": "attachment.vpc-id", "Values": [vid]}],
    )
    subnets = paginate(ec2, "describe_subnets", "Subnets", Filters=f)
    route_tables = paginate(ec2, "describe_route_tables", "RouteTables", Filters=f)
    nacls = paginate(ec2, "describe_network_acls", "NetworkAcls", Filters=f)
    groups = paginate(ec2, "describe_security_groups", "SecurityGroups", Filters=f)
    reservations = paginate(
        ec2, "describe_instances", "Reservations",
        Filters=f + [{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}],
    )
    instances = [i for r in reservations for i in r["Instances"]]

    # Which route table and NACL actually apply to each subnet.
    main_rt = next(
        (rt["RouteTableId"] for rt in route_tables
         for a in rt.get("Associations", []) if a.get("Main")),
        None,
    )
    subnet_rt = {
        a["SubnetId"]: rt["RouteTableId"]
        for rt in route_tables for a in rt.get("Associations", []) if a.get("SubnetId")
    }
    subnet_nacl = {
        a["SubnetId"]: n["NetworkAclId"]
        for n in nacls for a in n.get("Associations", []) if a.get("SubnetId")
    }

    snapshot = {
        "schema_version": 1,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "region": session.region_name,
        "vpc": {"id": vid, "name": tag(vpc, "Name"), "cidr": vpc["CidrBlock"]},
        "internet_gateways": sorted(
            [{"id": g["InternetGatewayId"], "name": tag(g, "Name")} for g in igws],
            key=lambda g: g["id"],
        ),
        "subnets": sorted(
            [
                {
                    "id": s["SubnetId"],
                    "name": tag(s, "Name"),
                    "cidr": s["CidrBlock"],
                    "availability_zone": s["AvailabilityZone"],
                    "map_public_ip_on_launch": s.get("MapPublicIpOnLaunch", False),
                    "route_table_id": subnet_rt.get(s["SubnetId"], main_rt),
                    "route_table_explicit": s["SubnetId"] in subnet_rt,
                    "network_acl_id": subnet_nacl.get(s["SubnetId"]),
                }
                for s in subnets
            ],
            key=lambda s: s["cidr"],
        ),
        "route_tables": sorted(
            [
                {
                    "id": rt["RouteTableId"],
                    "name": tag(rt, "Name"),
                    "main": any(a.get("Main") for a in rt.get("Associations", [])),
                    "subnet_ids": sorted(a["SubnetId"] for a in rt.get("Associations", []) if a.get("SubnetId")),
                    "routes": [normalize_route(r) for r in rt.get("Routes", [])],
                }
                for rt in route_tables
            ],
            key=lambda rt: rt["id"],
        ),
        "network_acls": sorted(
            [
                {
                    "id": n["NetworkAclId"],
                    "name": tag(n, "Name"),
                    "default": n.get("IsDefault", False),
                    "subnet_ids": sorted(a["SubnetId"] for a in n.get("Associations", []) if a.get("SubnetId")),
                    # Evaluation order matters: lowest rule number wins.
                    "ingress": sorted(
                        [normalize_nacl_entry(e) for e in n["Entries"] if not e["Egress"]],
                        key=lambda e: e["rule_no"],
                    ),
                    "egress": sorted(
                        [normalize_nacl_entry(e) for e in n["Entries"] if e["Egress"]],
                        key=lambda e: e["rule_no"],
                    ),
                }
                for n in nacls
            ],
            key=lambda n: n["id"],
        ),
        "security_groups": sorted(
            [
                {
                    "id": g["GroupId"],
                    "name": g["GroupName"],
                    # Free text an attacker could control. Treat as data, never as instructions.
                    "description": g.get("Description"),
                    "ingress": flatten_permissions(g.get("IpPermissions", [])),
                    "egress": flatten_permissions(g.get("IpPermissionsEgress", [])),
                }
                for g in groups
            ],
            key=lambda g: g["name"],
        ),
        "instances": sorted(
            [
                {
                    "id": i["InstanceId"],
                    "name": tag(i, "Name"),
                    "role": tag(i, "Role"),
                    "state": i["State"]["Name"],
                    "subnet_id": i.get("SubnetId"),
                    "private_ip": i.get("PrivateIpAddress"),
                    "public_ip": i.get("PublicIpAddress"),
                    "security_group_ids": sorted(sg["GroupId"] for sg in i.get("SecurityGroups", [])),
                    "imdsv2_required": (i.get("MetadataOptions") or {}).get("HttpTokens") == "required",
                }
                for i in instances
            ],
            key=lambda i: (i["role"] or "", i["id"]),
        ),
    }
    return snapshot


def summarize(snapshot: dict) -> str:
    counts = {k: len(snapshot[k]) for k in
              ["internet_gateways", "subnets", "route_tables", "network_acls", "security_groups", "instances"]}
    rules = sum(len(g["ingress"]) for g in snapshot["security_groups"])
    return (
        f"VPC {snapshot['vpc']['id']} ({snapshot['vpc']['cidr']}): "
        + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in counts.items())
        + f", {rules} security group ingress rules"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--role-arn", default=os.environ.get("AUDITOR_ROLE_ARN"),
                        help="Read-only role to assume (default: $AUDITOR_ROLE_ARN)")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--vpc-id", help="Collect this VPC instead of finding it by Project tag")
    parser.add_argument("--project", default="network-auditor")
    parser.add_argument("--out", type=Path, help="Output file (default: snapshots/live/<timestamp>.json)")
    args = parser.parse_args(argv)

    if not args.role_arn:
        print("warning: no --role-arn given, running with your own credentials", file=sys.stderr)

    snapshot = collect(make_session(args.role_arn, args.region), args.vpc_id, args.project)

    out = args.out or Path("snapshots/live") / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, indent=2) + "\n")
    print(summarize(snapshot))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
