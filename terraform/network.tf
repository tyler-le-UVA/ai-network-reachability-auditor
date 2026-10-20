# Lab network: one VPC, a public subnet (web tier) and a private subnet (db tier).
# Planted misconfigurations are marked "PLANTED Pn" and listed in answer_key/expected_findings.yaml.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project}-vpc" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = { Name = "${var.project}-igw" }
}

# ---------- Subnets ----------

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1) # 10.20.1.0/24
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${var.project}-public", Tier = "public" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 2) # 10.20.2.0/24
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = { Name = "${var.project}-private", Tier = "private" }
}

# ---------- Route tables ----------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "${var.project}-public-rt" }
}

# PLANTED P4: the "private" subnet's route table sends 0.0.0.0/0 straight to the
# internet gateway. The db host has no public IP, so it isn't reachable from the
# internet today, but any instance launched here with a public IP would be.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "${var.project}-private-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# ---------- Network ACL (public subnet) ----------
# The private subnet keeps the VPC's default NACL (allow all).

resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.lab.id
  subnet_ids = [aws_subnet.public.id]

  # PLANTED P5: denies inbound HTTP before the allow-all rule. The web security
  # group allows port 80, so a checker that only reads security groups will
  # wrongly report HTTP as reachable. NACLs are evaluated lowest rule number first.
  ingress {
    rule_no    = 90
    protocol   = "tcp"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.project}-public-nacl" }
}
