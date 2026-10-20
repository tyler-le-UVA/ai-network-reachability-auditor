output "smoke_test_parameter" {
  value = aws_ssm_parameter.smoke_test.name
}

output "applied_tags" {
  description = "Tags actually applied, including provider default_tags"
  value       = aws_ssm_parameter.smoke_test.tags_all
}
