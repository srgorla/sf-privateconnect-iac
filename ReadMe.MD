# Salesforce Private Connect – AWS PrivateLink POC (Terraform)

This repository provisions a **Salesforce Private Connect (AWS PrivateLink) proof of concept** using Terraform.

It creates a private AWS backend (EC2 + internal Network Load Balancer) exposed via a **VPC Endpoint Service**, which Salesforce can connect to using **Private Connect**, without traversing the public internet.

The setup is designed for **short-lived AWS accounts** (e.g. Pluralsight labs) and can be recreated end-to-end in minutes.

---

## Architecture Overview

```
Salesforce Org
   |
   |  (Private Connect)
   |
AWS PrivateLink
   |
VPC Endpoint Service
   |
Internal Network Load Balancer (TCP : 80)
   |
Target Group (IP)
   |
EC2 Instance (Simple HTTP Server)
```

Key properties:
- No public internet access
- Internal NLB only
- Traffic flows entirely within AWS + Salesforce backbone
- Suitable for enterprise-grade integrations

---

## What This Terraform Creates

- Uses **default VPC** (for simplicity)
- EC2 instance running a simple HTTP server
- Internal Network Load Balancer
- Target Group (type: `ip`)
- Listener on **TCP port 80**
- VPC Endpoint Service (PrivateLink)
- Outputs the **endpoint service name** required by Salesforce

---

## Prerequisites

### Local Machine
- Terraform `>= 1.5`
- AWS CLI v2

Verify:
```bash
terraform version
aws --version
```

### AWS Account
- Permissions to create:
  - EC2
  - Security Groups
  - Network Load Balancer
  - Target Groups
  - VPC Endpoint Service (PrivateLink)
- Default VPC must exist

---

## AWS Authentication

Configure AWS CLI **locally** (never commit credentials):

```bash
aws configure --profile sf-privateconnect
```

Then export the profile:
```bash
export AWS_PROFILE=sf-privateconnect
```

Verify:
```bash
aws sts get-caller-identity
```

---

## Repository Structure

```
sf-privateconnect-iac/
├── main.tf        # AWS resources (EC2, NLB, PrivateLink)
├── variables.tf   # Input variables
├── outputs.tf     # Terraform outputs
└── ReadMe.MD
```

Best practices followed:
- Variables only in `variables.tf`
- Outputs only in `outputs.tf`
- No duplicated definitions

---

## Key Variables

Defined in `variables.tf`:

| Variable | Purpose |
|--------|--------|
| `aws_region` | AWS region (default: us-east-1) |
| `name_prefix` | Prefix for all AWS resources |
| `vpc_id` | Optional custom VPC (empty = default VPC) |
| `instance_type` | EC2 instance type |
| `acceptance_required` | Require manual endpoint acceptance |
| `allowed_principals` | Salesforce AWS principal ARN(s) |

---

## Deploying the Infrastructure

Recommended approach is to override `name_prefix` at runtime to avoid name collisions.

```bash
terraform init
terraform plan  -var="name_prefix=sf-privateconnect-01"
terraform apply -var="name_prefix=sf-privateconnect-01"
```

---

## Outputs (Important)

After apply:

```bash
terraform output
```

Key output:

```
endpoint_service_name = com.amazonaws.vpce.us-east-1.vpce-svc-xxxxxxxx
```

This value is required in **Salesforce Setup → Private Connect**.

---

## Salesforce Side (High-Level)

1. Go to **Setup → Private Connect**
2. Create a new Private Connection
3. Paste the **endpoint service name** from Terraform output
4. (POC) Use **Legacy Named Credential** with `http://`
5. Test callout using Apex

TLS / HTTPS can be added later using ACM + domain if account permissions allow.

---

## Verifying AWS Side

Terraform does not wait for target health checks.

Verify target group health manually:

```bash
aws elbv2 describe-target-health \
  --target-group-arn "$(terraform output -raw target_group_arn)"
```

Target status should be `healthy`.

---

## Cleanup

To destroy the stack:

```bash
terraform destroy -var="name_prefix=sf-privateconnect-01"
```

---

## Notes & Limitations

- Designed for **POC / sandbox** usage
- Uses HTTP (port 80) to avoid TLS/domain requirements
- Production setup should:
  - Use HTTPS
  - Terminate TLS at NLB
  - Restrict `allowed_principals`
  - Lock down security groups

---

## Reusing in a New AWS Account

1. Configure AWS CLI
2. Clone repo
3. Run `terraform init`
4. Use a **new `name_prefix`**
5. Apply
6. Wire Salesforce Private Connect

No manual AWS console steps required.

---

## Status

- Terraform validated
- Multiple infra stacks created successfully
- Salesforce Private Connect compatible
- Ready for reuse in new AWS accounts
