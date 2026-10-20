variable "region" {
  description = "AWS region for the lab"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project tag applied to every resource (used for cost tracking)"
  type        = string
  default     = "network-auditor"
}

variable "repo_name" {
  description = "GitHub repo this infrastructure belongs to"
  type        = string
  default     = "ai-network-reachability-auditor"
}
