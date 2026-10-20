# Milestone 2: the identity the auditor runs as.
# Read-only on purpose. Later milestones add only the specific extra actions they need
# (Reachability Analyzer in M3, Bedrock in M4), each as its own small policy.

data "aws_caller_identity" "current" {}

# Only the identity that runs `terraform apply` (your admin IAM user in CloudShell)
# may assume this role. A Lambda principal gets added if the tool is deployed later.
data "aws_iam_policy_document" "auditor_trust" {
  statement {
    sid     = "AllowOperatorToAssume"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.arn]
    }
  }
}

resource "aws_iam_role" "auditor" {
  name                 = "${var.project}-readonly"
  description          = "Read-only identity for the network reachability auditor"
  assume_role_policy   = data.aws_iam_policy_document.auditor_trust.json
  max_session_duration = 3600
}

# AWS-managed read-only security policy. Covers ec2:Describe* for VPCs, subnets,
# route tables, NACLs, security groups and instances. Grants no write actions.
resource "aws_iam_role_policy_attachment" "auditor_security_audit" {
  role       = aws_iam_role.auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

output "auditor_role_arn" {
  value = aws_iam_role.auditor.arn
}

output "auditor_trusted_principal" {
  description = "Who is allowed to assume the auditor role"
  value       = data.aws_caller_identity.current.arn
}
