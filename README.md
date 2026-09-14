# AWS SOAR Security Automation

This project demonstrates an event-driven Security Orchestration, Automation,
and Response (SOAR) architecture in AWS.

The solution uses GuardDuty, Security Hub, EventBridge, Step Functions,
Lambda, SNS, CloudTrail, and S3 to detect security findings, route them to
response playbooks, perform controlled containment actions, notify security
operations, and retain structured execution evidence.

The focus of the project is not simply automation. It is the architecture
around automated security response: detection routing, least privilege,
controlled containment, escalation, evidence collection, logging, and
resource lifecycle management.

## Architecture Overview

The primary event flow is:

**GuardDuty → Security Hub → EventBridge → Step Functions → Lambda**

Supporting services provide:

- SNS notifications and analyst escalation
- CloudTrail audit logging
- S3 execution artifacts and security-log retention
- CloudWatch workflow and Lambda logging
- KMS encryption for GuardDuty findings export

Two automated response scenarios are implemented.

### IAM Credential Compromise

For supported IAM-related findings, the workflow:

1. Enriches the finding with current IAM context.
2. Notifies the security team.
3. Disables active IAM user access keys.
4. Applies an emergency deny policy to the affected IAM user.
5. Tags the user to indicate quarantine status.
6. Escalates partial or failed response actions.
7. Writes a structured execution artifact to S3.

The containment is intentionally scoped to the affected IAM user. It does not
claim to revoke unrelated federated, IAM Identity Center, or assumed-role
sessions.

### EC2 Isolation

For supported EC2 threat findings, the workflow:

1. Enriches the finding with current EC2 context.
2. Notifies the security team.
3. Initiates EBS snapshots to support investigation and preservation.
4. Creates or reuses a restrictive quarantine security group.
5. Replaces the instance security groups with the quarantine group.
6. Escalates partial or failed containment actions.
7. Writes a structured execution artifact to S3.

The workflow is designed as containment rather than a claim of complete
network isolation. Additional controls could be required in a production
environment depending on the workload and network architecture.

## Security Design Decisions

Several design choices were made to keep automated response controlled and
auditable.

### Least-Privilege Execution Roles

Lambda functions use separate IAM execution roles based on their
responsibilities. Notification, enrichment, IAM containment, EC2 containment,
and audit-writing permissions are separated rather than placed into a single
broad automation role.

### Orchestrated Response

Step Functions coordinates enrichment, notification, containment, escalation,
and audit writing. Retry and failure paths are part of the workflow rather
than relying on individual Lambda functions to manage the complete response.

### Human Escalation

Automation does not assume every security response will succeed.

Partial or failed actions are routed to the notification path so an analyst
can review the finding and determine the next action.

### Audit Evidence

Each playbook execution can produce a structured S3 artifact containing the
finding, enrichment context, response results, notification information, and
execution metadata.

These artifacts support incident review, operational analysis, and evidence
collection within a broader security control environment.

## Audit Logging and Lifecycle Design

CloudTrail records AWS activity and sends logs to a versioned S3 audit bucket.
The project also uses the bucket for SOAR execution artifacts and GuardDuty
findings export.

During development, this design exposed an important lifecycle problem.

A large number of retained CloudTrail object versions accumulated in the
versioned bucket. Although the bucket appeared empty during cleanup, retained
versions and delete markers prevented Terraform from deleting it successfully.

The issue demonstrated that versioning, retention, cost, and infrastructure
lifecycle cannot be treated as separate architecture decisions.

The design was updated to include explicit lifecycle handling for current and
noncurrent object versions. Batched cleanup was also used to resolve the
existing retained-object backlog.

This became one of the central architecture lessons from the project:

> A security control can create operational and cost risk when its lifecycle
> behavior is not designed alongside the control itself.

## Testing and Validation

The project includes `tests/trigger_findings.sh` to exercise and inspect the
deployed pipeline.

The script supports:

- Generating GuardDuty IAM sample findings
- Generating GuardDuty EC2 sample findings
- Monitoring Step Functions executions
- Validating deployed SOAR components
- Inspecting generated S3 execution artifacts

This provides a repeatable way to exercise the architecture without presenting
the script as a full automated test suite.

## Infrastructure as Code

Terraform provisions the major architecture components through separate
modules:

- GuardDuty
- Security Hub
- EventBridge
- Step Functions
- Lambda
- IAM
- SNS
- CloudTrail and centralized logging
- S3 audit storage
- KMS encryption

The modular structure separates detection, orchestration, response,
notification, identity, and logging concerns.

## Operational Considerations

This project is a portfolio architecture and automation implementation rather
than a production-ready enterprise SOAR platform.

A production deployment would require additional decisions around:

- Multi-account and multi-region operation
- Organization-level GuardDuty and Security Hub administration
- Identity Center and federated-session containment
- Network architectures beyond security-group-based EC2 containment
- Formal evidence-retention requirements
- Centralized SIEM/SOC integration
- Change control and approval requirements for automated containment
- Expanded testing and failure injection
- Monitoring, SLOs, and operational ownership

## Documentation

Additional design and operational documentation is available in `docs/`:

- [Business Context](docs/business.md)
- [Technologies](docs/technologies.md)
- [Lessons Learned](docs/lessonslearned.md)
- [Compliance Mapping](docs/compliance_mapping.md)
- [Threat Model](docs/threat_model.md)
- [Operational Runbook](docs/operational_runbook.md)
- [Design Decisions](docs/design_decisions.md)
- [Cost Analysis](docs/cost_analysis.md)
- [Limitations](docs/limitations.md)
- [Scripts](docs/scripts.md)

## Key Takeaways

This project demonstrates several security architecture principles:

- Detection and response should be connected through explicit,
  observable workflows.
- Automated containment requires controlled permissions and failure paths.
- Human escalation remains necessary when automation is incomplete or fails.
- Security-response evidence should be generated as part of the workflow.
- Security controls must be evaluated for operational and cost impact.
- Infrastructure lifecycle behavior is part of security architecture, not
  merely a Terraform concern.

## Case Studies

- [Technical Case Study](TECHNICAL_CASE_STUDY.md)
- [Executive Case Study](EXECUTIVE_CASE_STUDY.md)
