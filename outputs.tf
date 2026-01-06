output "vpc_id" {
  description = "Selected VPC ID (default VPC if vpc_id var is empty)"
  value       = data.aws_vpc.selected.id
}

output "nlb_arn" {
  description = "ARN of the internal Network Load Balancer"
  value       = aws_lb.nlb.arn
}

output "nlb_dns_name" {
  description = "DNS name of the NLB (note: internal NLB is not reachable from the public internet)"
  value       = aws_lb.nlb.dns_name
}

output "ec2_instance_id" {
  description = "EC2 instance ID for the POC backend"
  value       = aws_instance.web.id
}

output "ec2_private_ip" {
  description = "Private IP of the EC2 backend (registered into the target group)"
  value       = aws_instance.web.private_ip
}

output "target_group_arn" {
  description = "ARN of the NLB target group"
  value       = aws_lb_target_group.tg.arn
}

output "endpoint_service_name" {
  description = "PrivateLink Endpoint Service Name to paste into Salesforce Private Connect"
  value       = aws_vpc_endpoint_service.endpoint_service.service_name
}

output "endpoint_service_id" {
  description = "VPC Endpoint Service ID"
  value       = aws_vpc_endpoint_service.endpoint_service.id
}