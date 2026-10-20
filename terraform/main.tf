# Milestone 0 smoke test: one free, harmless resource to prove that
# apply, default tags, remote state and destroy all work.
# Delete this once Milestone 1 adds the real lab network.
resource "aws_ssm_parameter" "smoke_test" {
  name  = "/${var.project}/smoke-test"
  type  = "String"
  value = "milestone-0"
}
