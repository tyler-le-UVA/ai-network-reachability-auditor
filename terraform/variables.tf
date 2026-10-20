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

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC"
  type        = string
  default     = "10.20.0.0/16"
}

variable "instance_type" {
  description = "Instance type for the lab hosts (keep it small; stop or destroy when idle)"
  type        = string
  default     = "t3.micro"
}
