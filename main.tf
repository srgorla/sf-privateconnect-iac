terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

########################################
# Provider
########################################

provider "aws" {
  region = var.aws_region
}

########################################
# Network: Use default VPC by default
########################################

data "aws_vpc" "default" {
  default = true
}

data "aws_vpc" "selected" {
  id = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default.id
}

data "aws_subnets" "selected" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.selected.id]
  }
}

locals {
  # For a POC, use all subnets in the selected VPC.
  nlb_subnet_ids = data.aws_subnets.selected.ids
}

########################################
# EC2: simple HTTP backend
########################################

resource "aws_security_group" "web_sg" {
  name        = "${var.name_prefix}-web-sg"
  description = "Allow HTTP inbound for POC web server"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"

    # For POC convenience. For tighter security, restrict to VPC CIDR or NLB subnets.
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-web-sg"
  }
}

# Amazon Linux 2023 AMI (x86_64)
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "web" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = local.nlb_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  # Not required for PrivateLink, but convenient for debugging the instance.
  associate_public_ip_address = true

  user_data = <<-EOF
              #!/bin/bash
              dnf update -y
              dnf install -y python3
              pip3 install flask

              cat << 'APP' > /opt/app.py
              from flask import Flask, jsonify
              app = Flask(__name__)

              @app.get("/poc")
              def poc():
                  return jsonify(ok=True, message="Hello from AWS via PrivateLink")

              app.run(host="0.0.0.0", port=80)
              APP

              python3 /opt/app.py &
              EOF

  tags = {
    Name = "${var.name_prefix}-web"
  }
}

########################################
# NLB + Target Group + Listener (TCP:80)
########################################

resource "aws_lb" "nlb" {
  name               = "${var.name_prefix}-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = local.nlb_subnet_ids

  tags = {
    Name = "${var.name_prefix}-nlb"
  }
}

resource "aws_lb_target_group" "tg" {
  name        = "${var.name_prefix}-tg"
  port        = 80
  protocol    = "TCP"
  vpc_id      = data.aws_vpc.selected.id
  target_type = "ip"

  # TCP health check is simplest for an NLB POC
  health_check {
    protocol = "TCP"
    port     = "80"
  }

  tags = {
    Name = "${var.name_prefix}-tg"
  }
}

# Register EC2 *private IP* as the target (because target group is type=ip)
resource "aws_lb_target_group_attachment" "tg_attach" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.web.private_ip
  port             = 80
}

# Listener on 80 so legacy Named Credential http://... works
resource "aws_lb_listener" "listener_80" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 80
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

########################################
# PrivateLink Endpoint Service
########################################

resource "aws_vpc_endpoint_service" "endpoint_service" {
  acceptance_required        = var.acceptance_required
  network_load_balancer_arns = [aws_lb.nlb.arn]

  # Optional: lock down who can connect (Salesforce IAM role principal ARN)
  allowed_principals = var.allowed_principals

  tags = {
    Name = "${var.name_prefix}-vpce-svc"
  }
}
