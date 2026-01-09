variable "aws_region" {
  type        = string
  description = "AWS region to deploy resources into"
  default     = "us-east-1"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for naming AWS resources"
  default     = "sf-privateconnect"
}

variable "vpc_id" {
  type        = string
  description = "Optional VPC ID to deploy into. If empty, the default VPC will be used."
  default     = ""
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type for the simple backend"
  default     = "t3.micro"
}

variable "allowed_azs" {
  type        = list(string)
  description = "List of AZs to use for subnets (helps avoid unsupported instance types)"
  default     = ["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d", "us-east-1f"]
}

variable "acceptance_required" {
  type        = bool
  description = "Whether the Endpoint Service requires acceptance"
  default     = true
}

variable "allowed_principals" {
  type        = list(string)
  description = "List of AWS IAM principals allowed to create endpoints to the service"
  default     = ["arn:aws:iam::412600517540:role/pvtconn-outbound-dp001-private-connect"]
}

variable "enable_ssm_endpoints" {
  type        = bool
  description = "Create SSM VPC interface endpoints (for Session Manager in private subnets)"
  default     = false
}

variable "enable_tls_listener" {
  type        = bool
  description = "Create a TLS listener on port 443 for the NLB"
  default     = false
}

variable "tls_cert_arn" {
  type        = string
  description = "ACM certificate ARN for the NLB TLS listener (required when enable_tls_listener is true)"
  default     = ""
}
