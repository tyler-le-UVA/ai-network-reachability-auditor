# Let the auditor call the specific Bedrock models it is evaluated with, and nothing else.
# Models are reached through US cross-region inference profiles, which may route a
# request to any US region they cover, so the foundation-model ARNs use a region wildcard.

variable "bedrock_model_ids" {
  description = "Inference profile IDs the AI auditor may use (first is the default)"
  type        = list(string)
  default = [
    "us.amazon.nova-2-lite-v1:0",
    "us.amazon.nova-lite-v1:0",
    "us.amazon.nova-micro-v1:0",
  ]
}

locals {
  # "us.amazon.nova-2-lite-v1:0" -> "amazon.nova-2-lite-v1:0"
  bedrock_foundation_models = [for id in var.bedrock_model_ids : replace(id, "/^[a-z]+\\./", "")]
}

data "aws_iam_policy_document" "auditor_bedrock" {
  statement {
    sid     = "InvokeAuditorModelsOnly"
    actions = ["bedrock:InvokeModel"] # Converse API calls are authorized as InvokeModel
    resources = concat(
      [for id in var.bedrock_model_ids :
      "arn:aws:bedrock:${var.region}:${data.aws_caller_identity.current.account_id}:inference-profile/${id}"],
      [for m in local.bedrock_foundation_models : "arn:aws:bedrock:*::foundation-model/${m}"],
    )
  }
}

resource "aws_iam_role_policy" "auditor_bedrock" {
  name   = "bedrock-auditor-model"
  role   = aws_iam_role.auditor.id
  policy = data.aws_iam_policy_document.auditor_bedrock.json
}

output "bedrock_model_ids" {
  value = var.bedrock_model_ids
}
