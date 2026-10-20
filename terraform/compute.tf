# Two small hosts so reachability questions have real sources and destinations.
# Nothing needs to run on them: Reachability Analyzer checks configuration, not live services.

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "web" {
  ami                         = data.aws_ssm_parameter.al2023.insecure_value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "required" # CONTROL C3: IMDSv2 only
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "${var.project}-web", Role = "web" }
}

resource "aws_instance" "db" {
  ami                         = data.aws_ssm_parameter.al2023.insecure_value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.db.id]
  associate_public_ip_address = false # CONTROL C2: no public IP

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "${var.project}-db", Role = "db" }
}
