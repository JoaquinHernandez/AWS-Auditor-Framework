# AWS-Auditor-Framework
# 🛡️ AWS-Auditor-Framework: Cloud Security & IAM Privilege Analysis Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen)](https://www.python.org/)
[![Cloud: AWS](https://img.shields.io/badge/Cloud-AWS-FF9900)](https://aws.amazon.com/)

A modular Python framework built with `boto3` to audit AWS IAM permissions, evaluate privilege escalation paths, identify resource exposure, and run non-destructive configuration assessments mapped to MITRE ATT&CK for Cloud.

---

## 🎯 Key Assessment Vectors
- **IAM Privilege Escalation Surface:** Identifies 20+ known IAM permission combinations leading to privilege escalation (e.g., `iam:PassRole` + `lambda:CreateFunction`, `iam:CreatePolicyVersion`).
- **Overly Permissive Role Trust Policies:** Flags trust policies containing `Principal: "*"` or missing external ID validation in cross-account roles.
- **Resource Exposure:** Detects public S3 buckets, unrestricted security groups (`0.0.0.0/0` on management ports), and unencrypted data volumes.
- **Credential Hygiene:** Identifies root account access keys, stale access keys (>90 days), and missing MFA on console users.

---

## 🚀 Quick Start

### 1. Installation
```bash
git clone [https://github.com/your-username/AWS-Auditor-Framework.git](https://github.com/your-username/AWS-Auditor-Framework.git)
cd AWS-Auditor-Framework
pip install -r requirements.txt

export AWS_DEFAULT_REGION="us-east-1"
# AWS CLI or SSO profile:
export AWS_PROFILE="audit-role"

python invoke_aws_auditor.py --export ./reports/aws_audit_report.json

python pentest/test_attack_vectors.py --output ./reports/pentest_results.json
