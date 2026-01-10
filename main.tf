terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }
  }
}

########################################
# Provider
########################################

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

########################################
# Network: Create a dedicated VPC
########################################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.allowed_azs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, var.public_subnet_newbits, count.index)
  availability_zone       = var.allowed_azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-public-${var.allowed_azs[count.index]}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.name_prefix}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

########################################
# Network: Private VPC for private API Gateway access
########################################

resource "aws_vpc" "private_api" {
  cidr_block           = var.private_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-private-api-vpc"
  }
}

resource "aws_subnet" "private_api" {
  count                   = length(var.allowed_azs)
  vpc_id                  = aws_vpc.private_api.id
  cidr_block              = cidrsubnet(var.private_vpc_cidr, var.private_subnet_newbits, count.index)
  availability_zone       = var.allowed_azs[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-private-api-${var.allowed_azs[count.index]}"
  }
}

resource "aws_security_group" "private_api_vpce_sg" {
  name        = "${var.name_prefix}-private-api-vpce-sg"
  description = "Allow HTTPS to the private API Gateway VPC endpoint"
  vpc_id      = aws_vpc.private_api.id

  ingress {
    description = "HTTPS from private VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.private_api.cidr_block]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-private-api-vpce-sg"
  }
}

resource "aws_vpc_endpoint" "private_api_execute_api" {
  vpc_id              = aws_vpc.private_api.id
  service_name        = "com.amazonaws.${var.aws_region}.execute-api"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_api[*].id
  security_group_ids  = [aws_security_group.private_api_vpce_sg.id]
}

resource "aws_vpc_endpoint" "private_api_ssm" {
  vpc_id              = aws_vpc.private_api.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_api[*].id
  security_group_ids  = [aws_security_group.private_api_vpce_sg.id]
}

resource "aws_vpc_endpoint" "private_api_ssmmessages" {
  vpc_id              = aws_vpc.private_api.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_api[*].id
  security_group_ids  = [aws_security_group.private_api_vpce_sg.id]
}

resource "aws_vpc_endpoint" "private_api_ec2messages" {
  vpc_id              = aws_vpc.private_api.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_api[*].id
  security_group_ids  = [aws_security_group.private_api_vpce_sg.id]
}

locals {
  # For a POC, use all public subnets in the VPC.
  nlb_subnet_ids      = sort(aws_subnet.public[*].id)
  instance_subnet_ids = sort(aws_subnet.public[*].id)
  lambda_subnet_ids   = sort(aws_subnet.public[*].id)
  s3_vpc_bucket_name  = var.s3_bucket_name != "" ? var.s3_bucket_name : "${var.name_prefix}-vpc-${random_id.s3_suffix.hex}"
  s3_public_bucket_name = var.s3_public_bucket_name != "" ? var.s3_public_bucket_name : "${var.name_prefix}-public-${random_id.s3_suffix.hex}"
  s3_privateconnect_bucket_name = var.s3_privateconnect_bucket_name != "" ? var.s3_privateconnect_bucket_name : "${var.name_prefix}-pc-${random_id.s3_suffix.hex}"
  s3_privateconnect_principals = length(var.s3_privateconnect_principals) > 0 ? var.s3_privateconnect_principals : var.allowed_principals
  s3_policy_admin_principals   = distinct(concat(var.s3_policy_admin_principals, [data.aws_caller_identity.current.arn]))
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
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"

    # For POC convenience. For tighter security, restrict to NLB subnets.
    cidr_blocks = [aws_vpc.main.cidr_block]
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
# S3: Public, VPC-only, and PrivateConnect-only buckets
########################################

resource "random_id" "s3_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "private" {
  bucket = local.s3_vpc_bucket_name

  tags = {
    Name = "${var.name_prefix}-vpc-bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "private" {
  bucket                  = aws_s3_bucket.private.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "private" {
  bucket = aws_s3_bucket.private.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private" {
  bucket = aws_s3_bucket.private.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "seed" {
  for_each = fileset("${path.module}/s3_files", "*")
  bucket   = aws_s3_bucket.private.id
  key      = each.value
  source   = "${path.module}/s3_files/${each.value}"
  etag     = filemd5("${path.module}/s3_files/${each.value}")
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id]

  tags = {
    Name = "${var.name_prefix}-s3-gateway-endpoint"
  }
}

data "aws_iam_policy_document" "s3_vpce_only" {
  statement {
    sid    = "DenyNonVpceAccess"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.private.arn,
      "${aws_s3_bucket.private.arn}/*",
    ]

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpce"
      values   = [aws_vpc_endpoint.s3.id]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = local.s3_policy_admin_principals
    }
  }
}

resource "aws_s3_bucket_policy" "private_vpce_only" {
  bucket = aws_s3_bucket.private.id
  policy = data.aws_iam_policy_document.s3_vpce_only.json

  depends_on = [aws_s3_object.seed]
}

resource "aws_s3_bucket" "public" {
  bucket = local.s3_public_bucket_name

  tags = {
    Name = "${var.name_prefix}-public-bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "public" {
  bucket = aws_s3_bucket.public.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "public" {
  bucket = aws_s3_bucket.public.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "public_seed" {
  for_each = fileset("${path.module}/s3_files", "*")
  bucket   = aws_s3_bucket.public.id
  key      = each.value
  source   = "${path.module}/s3_files/${each.value}"
  etag     = filemd5("${path.module}/s3_files/${each.value}")
}

data "aws_iam_policy_document" "s3_public_read" {
  count = var.enable_public_bucket_policy ? 1 : 0

  statement {
    sid     = "AllowPublicReadObjects"
    effect  = "Allow"
    actions = ["s3:GetObject"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = ["${aws_s3_bucket.public.arn}/*"]
  }

  statement {
    sid     = "AllowPublicListBucket"
    effect  = "Allow"
    actions = ["s3:ListBucket"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [aws_s3_bucket.public.arn]
  }
}

resource "aws_s3_bucket_policy" "public_read" {
  count  = var.enable_public_bucket_policy ? 1 : 0
  bucket = aws_s3_bucket.public.id
  policy = data.aws_iam_policy_document.s3_public_read[0].json

  depends_on = [aws_s3_object.public_seed]
}

resource "aws_s3_bucket" "privateconnect" {
  bucket = local.s3_privateconnect_bucket_name

  tags = {
    Name = "${var.name_prefix}-privateconnect-bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "privateconnect" {
  bucket                  = aws_s3_bucket.privateconnect.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "privateconnect" {
  bucket = aws_s3_bucket.privateconnect.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "privateconnect" {
  bucket = aws_s3_bucket.privateconnect.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "privateconnect_seed" {
  for_each = fileset("${path.module}/s3_files", "*")
  bucket   = aws_s3_bucket.privateconnect.id
  key      = each.value
  source   = "${path.module}/s3_files/${each.value}"
  etag     = filemd5("${path.module}/s3_files/${each.value}")
}

data "aws_iam_policy_document" "s3_privateconnect_only" {
  statement {
    sid    = "DenyNonApprovedPrincipals"
    effect = "Deny"

    not_principals {
      type        = "AWS"
      identifiers = concat(local.s3_privateconnect_principals, local.s3_policy_admin_principals)
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.privateconnect.arn,
      "${aws_s3_bucket.privateconnect.arn}/*",
    ]
  }

  statement {
    sid     = "AllowApprovedPrincipalsRead"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]

    principals {
      type        = "AWS"
      identifiers = local.s3_privateconnect_principals
    }

    resources = [
      aws_s3_bucket.privateconnect.arn,
      "${aws_s3_bucket.privateconnect.arn}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "privateconnect_only" {
  bucket = aws_s3_bucket.privateconnect.id
  policy = data.aws_iam_policy_document.s3_privateconnect_only.json

  depends_on = [aws_s3_object.privateconnect_seed]
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
  vpc_id      = aws_vpc.main.id
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
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
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
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = local.nlb_subnet_ids
  security_group_ids  = [aws_security_group.ssm_endpoint_sg[0].id]
}

resource "aws_vpc_endpoint" "ssmmessages" {
  count               = var.enable_ssm_endpoints ? 1 : 0
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = local.nlb_subnet_ids
  security_group_ids  = [aws_security_group.ssm_endpoint_sg[0].id]
}

resource "aws_vpc_endpoint" "ec2messages" {
  count               = var.enable_ssm_endpoints ? 1 : 0
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = local.nlb_subnet_ids
  security_group_ids  = [aws_security_group.ssm_endpoint_sg[0].id]
}

########################################
# Lambda + API Gateway (FAQ microservice)
########################################

resource "aws_iam_role" "faq_lambda_role" {
  name = "${var.name_prefix}-faq-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "faq_lambda_basic" {
  role       = aws_iam_role.faq_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "faq_lambda_vpc" {
  role       = aws_iam_role.faq_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_security_group" "faq_lambda_sg" {
  name        = "${var.name_prefix}-faq-lambda-sg"
  description = "Security group for FAQ Lambda"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-faq-lambda-sg"
  }
}

resource "aws_iam_role" "private_ssm_role" {
  name = "${var.name_prefix}-private-ssm-role"

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

resource "aws_iam_role_policy_attachment" "private_ssm_core" {
  role       = aws_iam_role.private_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "private_ssm_profile" {
  name = "${var.name_prefix}-private-ssm-profile"
  role = aws_iam_role.private_ssm_role.name
}

resource "aws_security_group" "private_ssm_sg" {
  name        = "${var.name_prefix}-private-ssm-sg"
  description = "Security group for private SSM test instance"
  vpc_id      = aws_vpc.private_api.id

  egress {
    description = "Allow HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.private_api.cidr_block]
  }

  egress {
    description = "Allow DNS to VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [aws_vpc.private_api.cidr_block]
  }

  egress {
    description = "Allow DNS to VPC resolver (TCP fallback)"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.private_api.cidr_block]
  }

  egress {
    description = "Allow IMDS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["169.254.169.254/32"]
  }

  tags = {
    Name = "${var.name_prefix}-private-ssm-sg"
  }
}

resource "aws_instance" "private_ssm_test" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private_api[0].id
  vpc_security_group_ids = [aws_security_group.private_ssm_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.private_ssm_profile.name
  associate_public_ip_address = false

  user_data = <<-EOF
              #!/bin/bash
              set -euo pipefail
              systemctl enable --now amazon-ssm-agent
              systemctl status amazon-ssm-agent --no-pager || true
              EOF

  tags = {
    Name = "${var.name_prefix}-private-ssm-test"
  }
}

data "archive_file" "faq_lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/faq"
  output_path = "${path.module}/lambda/faq.zip"
}

resource "aws_lambda_function" "faq" {
  function_name = "${var.name_prefix}-faq"
  description   = "Provide a random FAQ"
  role          = aws_iam_role.faq_lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs22.x"

  filename         = data.archive_file.faq_lambda_zip.output_path
  source_code_hash = data.archive_file.faq_lambda_zip.output_base64sha256

  vpc_config {
    subnet_ids         = local.lambda_subnet_ids
    security_group_ids = [aws_security_group.faq_lambda_sg.id]
  }

  depends_on = [
    aws_iam_role_policy_attachment.faq_lambda_basic,
    aws_iam_role_policy_attachment.faq_lambda_vpc,
  ]
}

resource "aws_api_gateway_rest_api" "faq" {
  name        = "${var.name_prefix}-faq-api"
  description = "Provide a random FAQ"
}

resource "aws_api_gateway_method" "faq_get_root" {
  rest_api_id   = aws_api_gateway_rest_api.faq.id
  resource_id   = aws_api_gateway_rest_api.faq.root_resource_id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "faq_lambda" {
  rest_api_id = aws_api_gateway_rest_api.faq.id
  resource_id = aws_api_gateway_rest_api.faq.root_resource_id
  http_method = aws_api_gateway_method.faq_get_root.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.faq.invoke_arn
}

resource "aws_lambda_permission" "faq_apigw" {
  statement_id  = "AllowExecutionFromApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.faq.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.faq.execution_arn}/*/*"
}

resource "aws_api_gateway_deployment" "faq" {
  rest_api_id = aws_api_gateway_rest_api.faq.id

  triggers = {
    redeploy = sha1(jsonencode([
      aws_api_gateway_method.faq_get_root.id,
      aws_api_gateway_integration.faq_lambda.id,
    ]))
  }

  depends_on = [aws_api_gateway_integration.faq_lambda]
}

resource "aws_api_gateway_stage" "faq" {
  rest_api_id   = aws_api_gateway_rest_api.faq.id
  deployment_id = aws_api_gateway_deployment.faq.id
  stage_name    = "myDeployment"
}

########################################
# Private API Gateway (FAQ microservice)
########################################

resource "aws_api_gateway_rest_api" "faq_private" {
  name        = "${var.name_prefix}-faq-private-api"
  description = "Provide a random FAQ (private)"

  endpoint_configuration {
    types = ["PRIVATE"]
  }
}

data "aws_iam_policy_document" "faq_private_api_policy" {
  statement {
    sid     = "AllowInvokeFromPrivateVpce"
    effect  = "Allow"
    actions = ["execute-api:Invoke"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = ["${aws_api_gateway_rest_api.faq_private.execution_arn}/*/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = [aws_vpc_endpoint.private_api_execute_api.id]
    }
  }
}

resource "aws_api_gateway_rest_api_policy" "faq_private" {
  rest_api_id = aws_api_gateway_rest_api.faq_private.id
  policy      = data.aws_iam_policy_document.faq_private_api_policy.json
}

resource "aws_api_gateway_method" "faq_private_get_root" {
  rest_api_id   = aws_api_gateway_rest_api.faq_private.id
  resource_id   = aws_api_gateway_rest_api.faq_private.root_resource_id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "faq_private_lambda" {
  rest_api_id = aws_api_gateway_rest_api.faq_private.id
  resource_id = aws_api_gateway_rest_api.faq_private.root_resource_id
  http_method = aws_api_gateway_method.faq_private_get_root.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.faq.invoke_arn
}

resource "aws_lambda_permission" "faq_private_apigw" {
  statement_id  = "AllowExecutionFromPrivateApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.faq.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.faq_private.execution_arn}/*/*"
}

resource "aws_api_gateway_deployment" "faq_private" {
  rest_api_id = aws_api_gateway_rest_api.faq_private.id

  triggers = {
    redeploy = sha1(jsonencode([
      aws_api_gateway_method.faq_private_get_root.id,
      aws_api_gateway_integration.faq_private_lambda.id,
    ]))
  }

  depends_on = [
    aws_api_gateway_integration.faq_private_lambda,
    aws_api_gateway_rest_api_policy.faq_private,
  ]
}

resource "aws_api_gateway_stage" "faq_private" {
  rest_api_id   = aws_api_gateway_rest_api.faq_private.id
  deployment_id = aws_api_gateway_deployment.faq_private.id
  stage_name    = "private"
}
