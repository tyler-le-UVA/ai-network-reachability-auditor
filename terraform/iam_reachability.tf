# Milestone 3: let the auditor run Reachability Analyzer.
# These actions create and delete the analyzer's own "path" and "analysis" objects.
# None of them can change a security group, NACL, route or instance, so the role
# still cannot modify the network (verify_readonly.py keeps proving that).

data "aws_iam_policy_document" "auditor_reachability" {
  statement {
    sid = "RunReachabilityAnalyzer"
    actions = [
      "ec2:CreateNetworkInsightsPath",
      "ec2:StartNetworkInsightsAnalysis",
      "ec2:DescribeNetworkInsightsPaths",
      "ec2:DescribeNetworkInsightsAnalyses",
    ]
    resources = ["*"]
  }

  statement {
    sid = "CleanUpOwnAnalyzerObjects"
    actions = [
      "ec2:DeleteNetworkInsightsPath",
      "ec2:DeleteNetworkInsightsAnalysis",
    ]
    resources = [
      "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:network-insights-path/*",
      "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:network-insights-analysis/*",
    ]
  }

  # Reachability Analyzer's backend service. Required for every analysis.
  statement {
    sid = "ReachabilityAnalyzerBackend"
    actions = [
      "tiros:CreateQuery",
      "tiros:GetQueryAnswer",
      "tiros:GetQueryExplanation",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "auditor_reachability" {
  name   = "reachability-analyzer"
  role   = aws_iam_role.auditor.id
  policy = data.aws_iam_policy_document.auditor_reachability.json
}
