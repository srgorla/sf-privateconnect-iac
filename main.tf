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

data "aws_subnets" "instance" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.selected.id]
  }

  # Avoid unsupported instance types in certain AZs.
  filter {
    name   = "availability-zone"
    values = var.allowed_azs
  }
}

locals {
  # For a POC, use all subnets in the selected VPC.
  nlb_subnet_ids = sort(data.aws_subnets.selected.ids)

  # Use a filtered set for the EC2 instance only.
  instance_subnet_ids = sort(data.aws_subnets.instance.ids)
}

########################################
# EC2: simple HTTP backend
########################################

resource "aws_iam_role" "web_ssm_role" {
  name = "${var.name_prefix}-web-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "web_ssm_core" {
  role       = aws_iam_role.web_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "web_ssm_profile" {
  name = "${var.name_prefix}-web-ssm-profile"
  role = aws_iam_role.web_ssm_role.name
}

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
  subnet_id              = local.instance_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.web_ssm_profile.name

  # Not required for PrivateLink, but convenient for debugging the instance.
  associate_public_ip_address = true

  user_data = <<-EOF
              #!/bin/bash
              dnf update -y
              dnf install -y python3
              dnf install -y python3-pip
              dnf install -y amazon-ssm-agent
              systemctl enable --now amazon-ssm-agent
              pip3 install flask

              cat << 'APP' > /opt/app.py
              from flask import Flask, jsonify
              app = Flask(__name__)

              @app.get("/hello")
              def hello():
                  # Use America/Chicago to render CST/CDT with timezone info.
                  from datetime import datetime
                  from zoneinfo import ZoneInfo
                  now_cst = datetime.now(ZoneInfo("America/Chicago"))
                  return jsonify(
                      ok=True,
                      message="Hello from AWS via PrivateLink",
                      timestamp_cst=now_cst.isoformat(),
                      timezone=str(now_cst.tzinfo),
                  )

              app.run(host="0.0.0.0", port=80)
              APP

              cat << 'SERVICE' > /etc/systemd/system/flask-app.service
              [Unit]
              Description=Flask app for PrivateLink POC
              After=network.target

              [Service]
              Type=simple
              ExecStart=/usr/bin/python3 /opt/app.py
              Restart=always
              RestartSec=2

              [Install]
              WantedBy=multi-user.target
              SERVICE

              systemctl daemon-reload
              systemctl enable --now flask-app
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

resource "aws_lb_listener" "listener_443" {
  count             = var.enable_tls_listener ? 1 : 0
  load_balancer_arn = aws_lb.nlb.arn
  port              = 443
  protocol          = "TLS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.tls_cert_arn

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

########################################
# Optional: VPC Endpoints for SSM
########################################

resource "aws_security_group" "ssm_endpoint_sg" {
  count       = var.enable_ssm_endpoints ? 1 : 0
  name        = "${var.name_prefix}-ssm-endpoint-sg"
  description = "Allow HTTPS to SSM VPC endpoints"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
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
    Name = "${var.name_prefix}-ssm-endpoint-sg"
  }
}

resource "aws_vpc_endpoint" "ssm" {
  count               = var.enable_ssm_endpoints ? 1 : 0
  vpc_id              = data.aws_vpc.selected.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = local.nlb_subnet_ids
  security_group_ids  = [aws_security_group.ssm_endpoint_sg[0].id]
}

resource "aws_vpc_endpoint" "ssmmessages" {
  count               = var.enable_ssm_endpoints ? 1 : 0
  vpc_id              = data.aws_vpc.selected.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = local.nlb_subnet_ids
  security_group_ids  = [aws_security_group.ssm_endpoint_sg[0].id]
}

resource "aws_vpc_endpoint" "ec2messages" {
  count               = var.enable_ssm_endpoints ? 1 : 0
  vpc_id              = data.aws_vpc.selected.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = local.nlb_subnet_ids
  security_group_ids  = [aws_security_group.ssm_endpoint_sg[0].id]
}
