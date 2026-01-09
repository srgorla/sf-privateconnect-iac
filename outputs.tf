output "vpc_id" {
  description = "VPC ID created for this stack"
  value       = aws_vpc.main.id
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

output "s3_bucket_name" {
  description = "Name of the VPC-only S3 bucket"
  value       = aws_s3_bucket.private.id
}

output "s3_vpc_endpoint_id" {
  description = "Gateway VPC endpoint ID for S3"
  value       = aws_vpc_endpoint.s3.id
}

output "s3_public_bucket_name" {
  description = "Name of the public S3 bucket"
  value       = aws_s3_bucket.public.id
}

output "s3_privateconnect_bucket_name" {
  description = "Name of the PrivateConnect-only S3 bucket"
  value       = aws_s3_bucket.privateconnect.id
}

output "faq_lambda_name" {
  description = "Name of the FAQ Lambda function"
  value       = aws_lambda_function.faq.function_name
}

output "faq_api_invoke_url" {
  description = "Invoke URL for the FAQ API Gateway stage"
  value       = "https://${aws_api_gateway_rest_api.faq.id}.execute-api.${var.aws_region}.amazonaws.com/${aws_api_gateway_stage.faq.stage_name}/"
}

output "private_api_vpc_id" {
  description = "VPC ID for the private API Gateway access"
  value       = aws_vpc.private_api.id
}

output "private_api_vpce_id" {
  description = "VPC endpoint ID for private API Gateway access"
  value       = aws_vpc_endpoint.private_api_execute_api.id
}

output "faq_private_api_invoke_url" {
  description = "Invoke URL for the private FAQ API (resolves inside the private VPC via the VPC endpoint)"
  value       = "https://${aws_api_gateway_rest_api.faq_private.id}.execute-api.${var.aws_region}.amazonaws.com/${aws_api_gateway_stage.faq_private.stage_name}/"
}
