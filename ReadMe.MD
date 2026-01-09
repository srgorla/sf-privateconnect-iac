# Salesforce Private Connect – AWS PrivateLink POC (Terraform)

This repository provisions a **Salesforce Private Connect (AWS PrivateLink) proof of concept** using Terraform.

It creates a private AWS backend (EC2 + internal Network Load Balancer) exposed via a **VPC Endpoint Service**, which Salesforce can connect to using **Private Connect**, without traversing the public internet. It also provisions a **FAQ Lambda + API Gateway** example wired into the same VPC.

The setup is designed for **short-lived AWS accounts** (e.g. Pluralsight labs) and can be recreated end-to-end in minutes.

---

## Architecture Overview

```
Salesforce Org
   |
   |  (Private Connect)
   |
AWS PrivateLink                         Amazon API Gateway
   |                                         |
VPC Endpoint Service                         |
   |                                         |
Internal Network Load Balancer (TCP : 80)    |
   |                                         |
Target Group (IP)                            |
   |                                         |
EC2 Instance (Simple HTTP Server)        Lambda (VPC-attached)
```

Key properties:
- No public internet access
- Internal NLB only
- Traffic flows entirely within AWS + Salesforce backbone
- Suitable for enterprise-grade integrations

---

## What This Terraform Creates

- Dedicated **VPC** with public subnets + internet gateway
- EC2 instance running a simple REST endpoint (`/hello`)
- Internal Network Load Balancer
- Target Group (type: `ip`)
- Listener on **TCP port 80**
- VPC Endpoint Service (PrivateLink)
- Outputs the **endpoint service name** required by Salesforce
- Endpoint service requires acceptance and is restricted to the Salesforce IAM role (see `allowed_principals`)
- EC2 instance uses SSM Session Manager (enabled by default); optional VPC endpoints for private subnets
- S3 buckets (public, VPC-only, PrivateConnect-only) seeded with sample files
- FAQ Lambda function deployed into the VPC
- API Gateway REST endpoint that invokes the FAQ Lambda

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
  - Lambda + API Gateway
  - S3 buckets and policies

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
├── lambda/faq     # FAQ Lambda source
├── s3_files       # Seed files for S3 buckets
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
| `vpc_cidr` | CIDR for the VPC |
| `public_subnet_newbits` | CIDR split size for public subnets |
| `allowed_azs` | AZs used for public subnets |
| `instance_type` | EC2 instance type |
| `acceptance_required` | Require manual endpoint acceptance (default: true) |
| `allowed_principals` | Salesforce AWS principal ARN(s) (default: provided role) |
| `enable_ssm_endpoints` | Create SSM VPC endpoints for private subnets (default: false) |
| `enable_tls_listener` | Enable NLB TLS listener (default: false) |
| `tls_cert_arn` | ACM cert ARN for NLB TLS listener |
| `s3_bucket_name` | Optional explicit bucket name for VPC-only bucket |
| `s3_public_bucket_name` | Optional explicit bucket name for public bucket |
| `enable_public_bucket_policy` | Attach public-read policy to public bucket (may be blocked in labs) |
| `s3_privateconnect_bucket_name` | Optional explicit bucket name for PrivateConnect-only bucket |
| `s3_privateconnect_principals` | IAM principals for PrivateConnect-only bucket |
| `s3_policy_admin_principals` | Extra principals allowed to manage S3 bucket policies |

---

## Deploying the Infrastructure

Recommended approach is to set `name_prefix` to avoid name collisions. If you want to keep multiple stacks, use a separate workspace or state file.

```bash
terraform init
terraform plan
terraform apply
```

### Multiple Stacks (Keep Old + New)

If you want to create a new stack without destroying the old one, use a separate state:

Workspace approach:
```bash
terraform workspace new lab02
terraform apply
```

State file approach:
```bash
terraform apply -state=terraform-lab02.tfstate
```

---

## Session Manager (No SSH Needed)

The EC2 instance is configured with the SSM agent and IAM role for Session Manager.

If your subnets are private (no internet/NAT), enable VPC endpoints:

```bash
terraform apply -var="enable_ssm_endpoints=true"
```

---

## Salesforce IAM Principal (Allowed Principals)

The endpoint service defaults to allowing the Salesforce IAM role below and requires acceptance:

```
arn:aws:iam::412600517540:role/pvtconn-outbound-dp001-private-connect
```

If you need to change it, override `allowed_principals` and/or `acceptance_required` at apply time.

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

FAQ API output:
```
faq_api_invoke_url = https://xxxxxxxxxx.execute-api.us-east-1.amazonaws.com/myDeployment/
```

---

## Salesforce Side (High-Level)

https://www.youtube.com/watch?v=KHE8pWnnpVE&t=169s

1. Go to **Setup → Private Connect**
2. Create a new Private Connection
3. Paste the **endpoint service name** from Terraform output
4. (POC) Use **Legacy Named Credential** with `http://`
   you can use nlb url - (ex: nlb_dns_name = "sf-privateconnect-01-nlb-532072e04e35fa9f.elb.us-east-1.amazonaws.com")
5. Test callout using Apex

TLS / HTTPS can be added later using ACM + domain if account permissions allow.
Note: Salesforce documentation focuses on connectivity, but HTTPS still requires a valid TLS certificate on the NLB for the hostname you use.

---

## Salesforce Named Credential Setup (POC)

### Why Named Credentials
Salesforce uses **Named Credentials** to define outbound callouts in a secure, reusable way.  
For this POC, we intentionally use **HTTP (port 80)** to avoid TLS certificates and domain ownership requirements (no Route 53 dependency).

This keeps the focus on validating **Private Connect + PrivateLink connectivity**.

---

### Option A: Legacy Named Credential (Recommended for POC)

> Use this option if HTTPS / certificates are not available.

1. Go to **Setup → Named Credentials**
2. Click **New (Legacy)**
3. Configure:
   - **Label**: `AWS PrivateLink Legacy`
   - **Name**: `AWS_PrivateLink_Legacy`
   - **URL**:  
     ```
     http://<internal-nlb-dns-name>
     ```
     Example:
     ```
     http://sf-privateconnect-01-nlb-xxxxxxxx.elb.us-east-1.amazonaws.com
     ```
   - **Identity Type**: Anonymous
   - **Authentication Protocol**: No Authentication
4. Save

> The internal NLB DNS name comes from the Terraform output:
```bash
terraform output nlb_dns_name
```

---

### Option B: New Named Credential (Private Connect Aware)

> Use this if your org supports **Private Connect + External Credentials**.

1. Go to **Setup → Named Credentials**
2. Click **New**
3. Configure:
   - **Label / Name**: `AWS PrivateLink`
   - **URL**:
     ```
     http://<internal-nlb-dns-name>
     ```
   - **External Credential**: Create a new one
     - Authentication: **No Authentication**
4. Under **Outbound Network Connection**, select:
   - Your **Private Connect** entry created earlier
5. Save

---

### Apex Test Callout

Use the Named Credential in Apex:

```apex
HttpRequest req = new HttpRequest();
//req.setEndpoint('callout:AWS_PrivateLink_Legacy/hello');
req.setEndpoint('callout:AWS_PrivateLink/hello');
req.setTimeout(12000);
req.setMethod('GET');

Http http = new Http();
HttpResponse res = http.send(req);

System.debug(res.getStatus());
System.debug(res.getBody());
```

Expected response (JSON) from the `/hello` REST endpoint:
```json
{
  "ok": true,
  "message": "Hello from AWS via PrivateLink",
  "timestamp_cst": "2024-01-01T12:34:56-06:00",
  "timezone": "America/Chicago"
}
```

---

### Common Troubleshooting

- **Read timed out**
  - Check Target Group health = `healthy`
  - Ensure EC2 security group allows port 80
- **Connection refused**
  - Listener not created on NLB
- **Named Credential cannot save**
  - Use Legacy Named Credential for HTTP
  - New Named Credential enforces HTTPS in some orgs

---

### Production Notes

For production:
- Use HTTPS (443)
- Attach ACM certificate to NLB
- Use a real domain (Route 53 or corporate DNS)
- Restrict `allowed_principals` to Salesforce AWS account

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
terraform destroy
```

If Terraform state gets stuck (common in short-lived lab accounts), you can wipe local state to start fresh:

```bash
rm -rf .terraform
rm -f terraform.tfstate terraform.tfstate.backup
```

Note: this only removes **local** state. AWS resources already created will remain unless you destroy them first.

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
4. Use a **new `name_prefix`** or a new workspace
5. Apply
6. Wire Salesforce Private Connect

Note: the S3 bucket policies automatically allow the current caller to manage them. If you use additional admin principals, set `s3_policy_admin_principals`.

No manual AWS console steps required.

---

## Status

- Terraform validated
- Multiple infra stacks created successfully
- Salesforce Private Connect compatible
- Ready for reuse in new AWS accounts
