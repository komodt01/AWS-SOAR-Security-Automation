# Compliance Control Mapping

This document maps each SOAR pipeline component to the specific security controls it satisfies across SOC 2 Type II, FedRAMP Moderate, and ISO 27001.

## AWS Service → Control Mapping

| AWS Service | Function | SOC 2 | FedRAMP | ISO 27001 |
|-------------|----------|-------|---------|-----------|
| AWS Security Hub | Centralized finding aggregation; continuous monitoring posture | CC7.2 | CA-7 | A.12.6.1 |
| Amazon GuardDuty | Threat detection; anomaly & malware identification | CC6.8 | SI-3, SI-4 | A.12.4.1 |
| Amazon EventBridge | Event-driven routing; policy-based orchestration trigger | CC7.3 | IR-4 | A.16.1.4 |
| AWS Step Functions | Playbook orchestration; stateful workflow with audit trail | CC4.2 | IR-4 | A.16.1.5 |
| AWS Lambda (iam_remediation) | Disable compromised credentials; enforce access restriction | CC6.1, CC6.8 | AC-2(3), AC-12 | A.9.4.1 |
| AWS Lambda (ec2_isolation) | Network isolation of compromised instance; boundary protection | CC6.6 | SC-7, IR-4 | A.16.1.5, A.13.1.3 |
| AWS Lambda (write_audit) | Immutable evidence artifact generation; audit log protection | CC4.1, CC5.3 | AU-2, AU-9 | A.12.4.1, A.16.1.7 |
| AWS SNS | SOC notification; incident alerting | CC7.3 | IR-6 | A.16.1.2 |
| AWS CloudTrail | Immutable API audit log; all SOAR actions recorded | CC5.3 | AU-2, AU-9 | A.12.4.1 |
| Amazon S3 (audit bucket) | Evidence storage; versioned, encrypted, object-locked | CC4.1 | AU-9 | A.12.4.2 |

---

## Playbook → Control Mapping

### Playbook 1: IAM Credential Compromise

| Step | Action | SOC 2 | FedRAMP | ISO 27001 |
|------|--------|-------|---------|-----------|
| 1 | Enrich finding with IAM user context | CC7.2 | IR-4 | A.16.1.4 |
| 2 | Alert SOC team via SNS | CC7.3 | IR-6 | A.16.1.2 |
| 3 | Disable active access keys | CC6.1 | AC-2(3) | A.9.4.1 |
| 4 | Attach DenyAll inline policy | CC6.8 | AC-12 | A.9.4.1 |
| 5 | Tag user as QUARANTINE | CC4.1 | IR-4 | A.16.1.5 |
| 6 | Write compliance artifact to S3 | CC5.3 | AU-2 | A.12.4.1 |

### Playbook 2: EC2 Isolation

| Step | Action | SOC 2 | FedRAMP | ISO 27001 |
|------|--------|-------|---------|-----------|
| 1 | Enrich finding with EC2/VPC/SG context | CC7.2 | IR-4 | A.16.1.4 |
| 2 | Alert SOC with instance details | CC7.3 | IR-6 | A.16.1.2 |
| 3 | Tag instance QUARANTINE_PENDING | CC7.2 | IR-4 | A.16.1.5 |
| 4 | Snapshot EBS volumes (forensic preservation) | CC4.1 | AU-14 | A.16.1.7 |
| 5 | Replace SGs with quarantine deny-all group | CC6.6 | SC-7 | A.13.1.3 |
| 6 | Write compliance artifact with snapshot IDs | CC5.3 | AU-2 | A.12.4.1 |

---

## Evidence Collection

Each playbook execution automatically generates a JSON evidence artifact stored at:

```
s3://<audit-bucket>/playbook-artifacts/<playbook-name>/<YYYY>/<MM>/<DD>/<finding-id>.json
```

The artifact captures:
- Original finding ID, type, severity, and affected resource
- Enrichment context (IAM user details or EC2 instance metadata)
- Every remediation action taken with status and timestamp
- Step Functions execution ID for cross-referencing execution history
- Explicit compliance control references for auditor consumption

This satisfies automated evidence collection requirements under SOC 2 CC4.1 (monitoring activities), FedRAMP AU-2 (audit events), and ISO 27001 A.12.4.1 (event logging) without manual collection effort.
