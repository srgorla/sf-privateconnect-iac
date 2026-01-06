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

variable "acceptance_required" {
  type        = bool
  description = "Whether the Endpoint Service requires acceptance"
  default     = false
}

variable "allowed_principals" {
  type        = list(string)
  description = "List of AWS IAM principals allowed to create endpoints to the service"
  default     = []
}