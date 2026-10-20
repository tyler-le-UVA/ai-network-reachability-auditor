"""Prove the auditor role can read the network but cannot change it.

Every write attempt uses EC2's DryRun flag, so nothing is ever modified:
  - DryRunOperation      -> the role WOULD be allowed to write  (FAIL)
  - UnauthorizedOperation -> the role is denied                  (PASS)

Usage (CloudShell, from the repo root):
    python3 collector/verify_readonly.py --role-arn "$(terraform -chdir=terraform output -raw auditor_role_arn)"
"""

from __future__ import annotations

import argparse
import os
import sys

from botocore.exceptions import ClientError

from collect import find_vpc, make_session


def dry_run(label: str, call) -> bool:
    """Run a DryRun write. Return True if the role is correctly denied."""
    try:
        call()
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code == "UnauthorizedOperation":
            print(f"  PASS  {label}: denied")
            return True
        if code == "DryRunOperation":
            print(f"  FAIL  {label}: role is ALLOWED to do this")
            return False
        print(f"  FAIL  {label}: unexpected error {code}")
        return False
    print(f"  FAIL  {label}: call succeeded without DryRun error")
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the auditor role is read-only")
    parser.add_argument("--role-arn", default=os.environ.get("AUDITOR_ROLE_ARN"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--project", default="network-auditor")
    args = parser.parse_args(argv)

    if not args.role_arn:
        print("error: pass --role-arn or set AUDITOR_ROLE_ARN", file=sys.stderr)
        return 2

    session = make_session(args.role_arn, args.region)
    ec2 = session.client("ec2")
    identity = session.client("sts").get_caller_identity()["Arn"]
    print(f"Running as: {identity}")

    # Reads must work.
    vpc = find_vpc(ec2, None, args.project)
    vpc_id = vpc["VpcId"]
    groups = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
    sg_id = next(g["GroupId"] for g in groups if g["GroupName"] != "default")
    print(f"  PASS  read: found VPC {vpc_id} and security group {sg_id}")

    # Writes must be denied.
    results = [
        dry_run("open port 9999 on a security group", lambda: ec2.authorize_security_group_ingress(
            GroupId=sg_id, DryRun=True,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 9999, "ToPort": 9999,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )),
        dry_run("delete a security group", lambda: ec2.delete_security_group(GroupId=sg_id, DryRun=True)),
        dry_run("tag the VPC", lambda: ec2.create_tags(
            Resources=[vpc_id], Tags=[{"Key": "tamper", "Value": "1"}], DryRun=True,
        )),
    ]

    passed = all(results)
    print("RESULT:", "read-only confirmed" if passed else "role can WRITE, fix its policies")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
