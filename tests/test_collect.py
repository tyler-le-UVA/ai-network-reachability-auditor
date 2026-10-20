"""Offline tests: build a small copy of the lab in moto (a fake AWS) and check
that the collector captures every planted issue in its normalized output."""

import json

import boto3
import pytest
from moto import mock_aws

import collect

REGION = "us-east-1"


@pytest.fixture
def lab():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)

        vpc_id = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
        ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Project", "Value": "network-auditor"},
                                                  {"Key": "Name", "Value": "network-auditor-vpc"}])
        igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)

        public = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
        private = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.20.2.0/24")["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=public, MapPublicIpOnLaunch={"Value": True})

        # Both route tables send 0.0.0.0/0 to the IGW (P4 is the private one).
        rts = {}
        for name, subnet in [("public", public), ("private", private)]:
            rt = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
            ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
            ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet)
            ec2.create_tags(Resources=[rt], Tags=[{"Key": "Name", "Value": f"network-auditor-{name}-rt"}])
            rts[name] = rt

        # Public NACL: deny tcp/80 at rule 90 before allow-all at 100 (P5).
        nacl = ec2.create_network_acl(VpcId=vpc_id)["NetworkAcl"]["NetworkAclId"]
        ec2.create_network_acl_entry(NetworkAclId=nacl, RuleNumber=100, Protocol="-1", RuleAction="allow",
                                     Egress=False, CidrBlock="0.0.0.0/0")
        ec2.create_network_acl_entry(NetworkAclId=nacl, RuleNumber=90, Protocol="6", RuleAction="deny",
                                     Egress=False, CidrBlock="0.0.0.0/0", PortRange={"From": 80, "To": 80})
        assoc = next(
            a["NetworkAclAssociationId"]
            for n in ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"]
            for a in n["Associations"] if a["SubnetId"] == public
        )
        ec2.replace_network_acl_association(AssociationId=assoc, NetworkAclId=nacl)

        web_sg = ec2.create_security_group(GroupName="network-auditor-web-sg", Description="Web tier",
                                           VpcId=vpc_id)["GroupId"]
        db_sg = ec2.create_security_group(GroupName="network-auditor-db-sg", Description="Database tier",
                                          VpcId=vpc_id)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=web_sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            for p in (22, 80, 443, 3389)
        ])
        ec2.authorize_security_group_ingress(GroupId=db_sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "10.20.0.0/16"}]}
        ])

        ami = ec2.describe_images()["Images"][0]["ImageId"]
        web = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=public,
                                SecurityGroupIds=[web_sg],
                                TagSpecifications=[{"ResourceType": "instance",
                                                    "Tags": [{"Key": "Role", "Value": "web"}]}])
        db = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=private,
                               SecurityGroupIds=[db_sg],
                               TagSpecifications=[{"ResourceType": "instance",
                                                   "Tags": [{"Key": "Role", "Value": "db"}]}])

        yield {
            "vpc_id": vpc_id, "igw": igw, "public": public, "private": private, "nacl": nacl,
            "rts": rts, "web_sg": web_sg, "db_sg": db_sg,
            "web_id": web["Instances"][0]["InstanceId"], "db_id": db["Instances"][0]["InstanceId"],
        }


@pytest.fixture
def snapshot(lab):
    return collect.collect(boto3.Session(region_name=REGION))


def sg(snapshot, name):
    return next(g for g in snapshot["security_groups"] if g["name"] == name)


def test_finds_lab_vpc_by_project_tag(lab, snapshot):
    assert snapshot["vpc"] == {"id": lab["vpc_id"], "name": "network-auditor-vpc", "cidr": "10.20.0.0/16"}


def test_internet_gateway_attached(lab, snapshot):
    assert [g["id"] for g in snapshot["internet_gateways"]] == [lab["igw"]]


def test_web_sg_has_all_world_open_ports(snapshot):
    rules = sg(snapshot, "network-auditor-web-sg")["ingress"]
    world = sorted(r["from_port"] for r in rules if r["source"] == "0.0.0.0/0")
    assert world == [22, 80, 443, 3389]  # P1, HTTP (P5), C1, P2
    assert all(r["protocol"] == "tcp" for r in rules)


def test_db_sg_allows_mysql_from_whole_vpc(snapshot):
    rules = sg(snapshot, "network-auditor-db-sg")["ingress"]
    assert rules == [{"protocol": "tcp", "from_port": 3306, "to_port": 3306,
                      "source_type": "cidr", "source": "10.20.0.0/16", "description": None}]  # P3


def test_private_subnet_resolves_to_route_with_igw(lab, snapshot):
    subnet = next(s for s in snapshot["subnets"] if s["id"] == lab["private"])
    assert subnet["route_table_id"] == lab["rts"]["private"]
    assert subnet["route_table_explicit"] is True
    rt = next(r for r in snapshot["route_tables"] if r["id"] == lab["rts"]["private"])
    assert {"destination": "0.0.0.0/0", "target_type": "internet_gateway",
            "target_id": lab["igw"], "state": "active"} in rt["routes"]  # P4
    assert any(r["target_type"] == "local" for r in rt["routes"])


def test_public_nacl_rules_sorted_with_deny_first(lab, snapshot):
    subnet = next(s for s in snapshot["subnets"] if s["id"] == lab["public"])
    assert subnet["network_acl_id"] == lab["nacl"]
    nacl = next(n for n in snapshot["network_acls"] if n["id"] == lab["nacl"])
    first, second = nacl["ingress"][0], nacl["ingress"][1]
    assert (first["rule_no"], first["action"], first["protocol"], first["from_port"]) == (90, "deny", "tcp", 80)  # P5
    assert (second["rule_no"], second["action"], second["protocol"]) == (100, "allow", "all")


def test_instances_mapped_to_subnets_and_groups(lab, snapshot):
    by_role = {i["role"]: i for i in snapshot["instances"]}
    assert by_role["web"]["subnet_id"] == lab["public"]
    assert by_role["web"]["security_group_ids"] == [lab["web_sg"]]
    assert by_role["db"]["subnet_id"] == lab["private"]
    assert by_role["db"]["security_group_ids"] == [lab["db_sg"]]


def test_snapshot_is_json_serializable_and_stable(lab):
    session = boto3.Session(region_name=REGION)
    a = collect.collect(session)
    b = collect.collect(session)
    a.pop("collected_at"), b.pop("collected_at")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_assumes_role_when_given(lab):
    session = collect.make_session("arn:aws:iam::123456789012:role/network-auditor-readonly", REGION)
    arn = session.client("sts").get_caller_identity()["Arn"]
    assert "assumed-role/network-auditor-readonly/network-auditor-collector" in arn


def test_missing_vpc_gives_clear_error():
    with mock_aws():
        with pytest.raises(SystemExit, match="Expected exactly one VPC"):
            collect.collect(boto3.Session(region_name=REGION))


def test_flatten_handles_all_traffic_and_sg_sources():
    rules = collect.flatten_permissions([
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
         "UserIdGroupPairs": [{"GroupId": "sg-web", "Description": "from web"}]},
    ])
    assert rules[0] == {"protocol": "all", "from_port": None, "to_port": None,
                        "source_type": "cidr", "source": "0.0.0.0/0", "description": None}
    assert rules[1]["source_type"] == "security_group" and rules[1]["source"] == "sg-web"
