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

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the new VPC"
  default     = "10.0.0.0/16"
}

variable "public_subnet_newbits" {
  type        = number
  description = "New bits for public subnet CIDR calculation (vpc_cidr is split by this many bits)"
  default     = 8
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

variable "s3_bucket_name" {
  type        = string
  description = "Optional explicit S3 bucket name for the VPC-only bucket (must be globally unique); empty means auto-generate"
  default     = ""
}

variable "s3_public_bucket_name" {
  type        = string
  description = "Optional explicit S3 bucket name for the public bucket (must be globally unique); empty means auto-generate"
  default     = ""
}

variable "enable_public_bucket_policy" {
  type        = bool
  description = "Attach public-read bucket policy to the public bucket (may be blocked by account-level S3 settings)"
  default     = true
}

variable "s3_privateconnect_bucket_name" {
  type        = string
  description = "Optional explicit S3 bucket name for the PrivateConnect-only bucket (must be globally unique); empty means auto-generate"
  default     = ""
}

variable "s3_privateconnect_principals" {
  type        = list(string)
  description = "IAM principals allowed to access the PrivateConnect-only bucket; empty uses allowed_principals"
  default     = []
}

variable "s3_policy_admin_principals" {
  type        = list(string)
  description = "IAM principals allowed to manage S3 bucket policies (exempt from policy denies)"
  default     = []
}
