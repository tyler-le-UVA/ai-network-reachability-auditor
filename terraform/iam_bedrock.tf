# Milestone 4: let the auditor call one Bedrock model and nothing else.
# Nova 2 Lite is reached through the US cross-region inference profile, which may
# route a request to any of the US regions it covers, so the foundation-model ARN
# uses a region wildcard.

variable "bedrock_model_id" {
  description = "Inference profile ID of the model the AI auditor uses"
  type        = string
  default     = "us.amazon.nova-2-lite-v1:0"
}

locals {
  # "us.amazon.nova-2-lite-v1:0" -> "amazon.nova-2-lite-v1:0"
  bedrock_foundation_model = replace(var.bedrock_model_id, "/^[a-z]+\\./", "")
}

data "aws_iam_policy_document" "auditor_bedrock" {
  statement {
    sid     = "InvokeAuditorModelOnly"
    actions = ["bedrock:InvokeModel"] # Converse API calls are authorized as InvokeModel
    resources = [
      "arn:aws:bedrock:${var.region}:${data.aws_caller_identity.current.account_id}:inference-profile/${var.bedrock_model_id}",
      "arn:aws:bedrock:*::foundation-model/${local.bedrock_foundation_model}",
    ]
  }
}

resource "aws_iam_role_policy" "auditor_bedrock" {
  name   = "bedrock-auditor-model"
  role   = aws_iam_role.auditor.id
  policy = data.aws_iam_policy_document.auditor_bedrock.json
}

output "bedrock_model_id" {
  value = var.bedrock_model_id
}
