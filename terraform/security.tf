# Security groups for the web and db tiers.
# Rules are separate resources so each planted issue is its own addressable resource.

# ---------- Web tier ----------

resource "aws_security_group" "web" {
  name        = "${var.project}-web-sg"
  description = "Web tier"
  vpc_id      = aws_vpc.lab.id

  tags = { Name = "${var.project}-web-sg" }
}

# PLANTED P1: SSH open to the entire internet.
resource "aws_vpc_security_group_ingress_rule" "web_ssh_world" {
  security_group_id = aws_security_group.web.id
  description       = "SSH from anywhere"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

# PLANTED P2: RDP open to the internet on a Linux host that doesn't use it.
resource "aws_vpc_security_group_ingress_rule" "web_rdp_world" {
  security_group_id = aws_security_group.web.id
  description       = "RDP from anywhere"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv4         = "0.0.0.0/0"
}

# Intended, but blocked by the public NACL (see PLANTED P5 in network.tf).
resource "aws_vpc_security_group_ingress_rule" "web_http_world" {
  security_group_id = aws_security_group.web.id
  description       = "HTTP from anywhere"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

# CONTROL C1: intentional public HTTPS. The auditor should NOT flag this.
resource "aws_vpc_security_group_ingress_rule" "web_https_world" {
  security_group_id = aws_security_group.web.id
  description       = "HTTPS from anywhere"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "web_all_out" {
  security_group_id = aws_security_group.web.id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ---------- DB tier ----------

resource "aws_security_group" "db" {
  name        = "${var.project}-db-sg"
  description = "Database tier"
  vpc_id      = aws_vpc.lab.id

  tags = { Name = "${var.project}-db-sg" }
}

# PLANTED P3: MySQL allowed from the whole VPC instead of only the web tier.
# Correct version: referenced_security_group_id = aws_security_group.web.id
resource "aws_vpc_security_group_ingress_rule" "db_mysql_vpc" {
  security_group_id = aws_security_group.db.id
  description       = "MySQL from VPC"
  ip_protocol       = "tcp"
  from_port         = 3306
  to_port           = 3306
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "db_all_out" {
  security_group_id = aws_security_group.db.id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
