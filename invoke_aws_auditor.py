#!/usr/bin/env python3
"""
AWS-Auditor-Framework - Core Audit Engine
Evaluates IAM hygiene, credential freshness, S3 bucket exposure, and Security Groups.
"""

import argparse
import json
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError


class AWSAuditor:
    def __init__(self):
        self.findings = []
        self.iam = boto3.client("iam")
        self.s3 = boto3.client("s3")
        self.ec2 = boto3.client("ec2")

    def add_finding(self, category: str, severity: str, title: str, details: str, remediation: str):
        self.findings.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": category,
            "severity": severity,
            "title": title,
            "details": details,
            "remediation": remediation
        })

    def audit_iam_credentials(self):
        print("[*] Auditing IAM Users & Credential Hygiene...")
        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    
                    # 1. MFA Check for Console Access
                    try:
                        self.iam.get_login_profile(UserName=username)
                        mfa_devices = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
                        if not mfa_devices:
                            self.add_finding(
                                category="IAM Hygiene",
                                severity="High",
                                title="Console User Without MFA",
                                details=f"User '{username}' has console login capability but no active MFA device.",
                                remediation=f"Enforce MFA for user '{username}' via IAM or Identity Center."
                            )
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "NoSuchEntity":
                            pass

                    # 2. Access Key Age Check (>90 days)
                    keys = self.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                    for key in keys:
                        if key["Status"] == "Active":
                            age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                            if age_days > 90:
                                self.add_finding(
                                    category="Credential Hygiene",
                                    severity="Medium",
                                    title="Stale IAM Access Key Detected",
                                    details=f"User '{username}' has active key '{key['AccessKeyId']}' created {age_days} days ago.",
                                    remediation="Rotate access keys every 90 days or migrate to IAM Roles / AWS IAM Identity Center."
                                )
        except ClientError as err:
            print(f"[-] IAM audit error: {err}")

    def audit_role_trust_policies(self):
        print("[*] Scanning IAM Role Trust Relationships for Wildcards...")
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    role_name = role["RoleName"]
                    trust_doc = role.get("AssumeRolePolicyDocument", {})
                    statements = trust_doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    for stmt in statements:
                        if stmt.get("Effect") == "Allow":
                            principal = stmt.get("Principal", {})
                            if principal == "*" or principal.get("AWS") == "*":
                                condition = stmt.get("Condition")
                                if not condition:
                                    self.add_finding(
                                        category="Trust Relationships",
                                        severity="Critical",
                                        title="Overly Permissive Role Trust Policy",
                                        details=f"Role '{role_name}' allows assume role from wildcard principal ('*') without conditions.",
                                        remediation="Scope the Principal field to specific trusted ARNs and require ExternalId/SourceArn conditions."
                                    )
        except ClientError as err:
            print(f"[-] Role trust audit error: {err}")

    def audit_s3_buckets(self):
        print("[*] Auditing S3 Bucket Public Access Block Settings...")
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
            for b in buckets:
                name = b["Name"]
                try:
                    pab = self.s3.get_public_access_block(Bucket=name)
                    config = pab.get("PublicAccessBlockConfiguration", {})
                    if not all([
                        config.get("BlockPublicAcls"),
                        config.get("IgnorePublicAcls"),
                        config.get("BlockPublicPolicy"),
                        config.get("RestrictPublicBuckets")
                    ]):
                        self.add_finding(
                            category="S3 Exposure",
                            severity="High",
                            title="S3 Public Access Block Incomplete",
                            details=f"Bucket '{name}' does not have all 4 S3 Public Access Block protections enabled.",
                            remediation=f"Enable all S3 Public Access Block settings on bucket '{name}'."
                        )
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                        self.add_finding(
                            category="S3 Exposure",
                            severity="High",
                            title="Missing S3 Public Access Block Configuration",
                            details=f"Bucket '{name}' has no Public Access Block configuration applied.",
                            remediation=f"Apply Public Access Block configuration to bucket '{name}'."
                        )
        except ClientError as err:
            print(f"[-] S3 audit error: {err}")

    def audit_security_groups(self):
        print("[*] Inspecting EC2 Security Groups for Exposed Management Ports...")
        sensitive_ports = {22: "SSH", 3389: "RDP", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS"}
        try:
            sgs = self.ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    ip_ranges = [r.get("CidrIp") for r in rule.get("IpRanges", [])]

                    if "0.0.0.0/0" in ip_ranges:
                        for port, service in sensitive_ports.items():
                            if from_port is not None and to_port is not None and from_port <= port <= to_port:
                                self.add_finding(
                                    category="Network Exposure",
                                    severity="Critical",
                                    title=f"Unrestricted {service} Access (Port {port})",
                                    details=f"Security Group '{sg_name}' ({sg_id}) exposes {service} to 0.0.0.0/0.",
                                    remediation=f"Restrict inbound access on port {port} to specific administrative IP ranges."
                                )
        except ClientError as err:
            print(f"[-] Security group audit error: {err}")

    def run_all(self, export_path: str):
        print("=" * 60)
        print("   AWS AUDITOR FRAMEWORK - ENVIRONMENT AUDIT ENGINE   ")
        print("=" * 60)
        self.audit_iam_credentials()
        self.audit_role_trust_policies()
        self.audit_s3_buckets()
        self.audit_security_groups()

        print("\n[+] Audit Complete. Findings Summary:")
        severity_counts = {}
        for f in self.findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev, count in sorted(severity_counts.items()):
            print(f"  - {sev}: {count}")

        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2)
        print(f"\n[+] Full report exported to: {export_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS Security & Privilege Auditor")
    parser.add_argument("--export", default="./AWS_Audit_Report.json", help="Output path for JSON report")
    args = parser.parse_args()

    auditor = AWSAuditor()
    auditor.run_all(export_path=args.export)
