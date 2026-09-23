# AWS SOAR Security Automation

## Overview

This project demonstrates an event-driven Security Orchestration, Automation, and Response (SOAR) architecture in AWS.

The implementation connects cloud threat detection to controlled response workflows using:

**GuardDuty → Security Hub → EventBridge → Step Functions → Lambda**

The project focuses on more than automating remediation. It explores the architecture required to give security automation privileged authority safely:

* Detection and event qualification.
* Orchestrated response.
* Least-privilege automation identities.
* IAM and EC2 containment.
* Failure and partial-response handling.
* Human escalation.
* Audit evidence.
* Logging and retention.
* Infrastructure lifecycle management.

The central design question is not simply whether a response can be automated.

It is how much authority automation should receive, under what conditions, and what happens when the automated response cannot complete safely.

---

## Architecture

The implemented event flow is:

```text
GuardDuty
    |
    v
Security Hub
    |
    v
EventBridge
    |
    v
Step Functions
    |
    +--> Enrich Finding
    |
    +--> Notify Security Operations
    |
    +--> IAM or EC2 Containment
    |
    +--> Evaluate Result
    |
    +--> Escalate When Required
    |
    +--> Write Execution Evidence
```

Supporting services include:

* SNS for security notifications.
* CloudWatch for Lambda and workflow logging.
* CloudTrail for AWS API audit activity.
* S3 for security logs and structured response artifacts.
* KMS for GuardDuty findings-export encryption.

Terraform provisions the major components through separate modules for detection, orchestration, response, identity, notification, and logging.

---

## Automated Response Scenarios

Two response scenarios are implemented.

### IAM Credential Compromise

EventBridge routes supported HIGH or CRITICAL GuardDuty IAM findings imported through Security Hub to the IAM response state machine.

The workflow:

1. Enriches the finding with current IAM context.
2. Notifies the security team.
3. Disables active IAM user access keys.
4. Applies an emergency explicit-deny policy.
5. Tags the affected IAM user to indicate quarantine status.
6. Evaluates the remediation result.
7. Escalates partial or failed containment.
8. Writes structured execution evidence to S3.

The response is intentionally scoped to the affected IAM user.

It does not claim to revoke unrelated federated, IAM Identity Center, or assumed-role sessions.

Those identity mechanisms would require additional containment procedures in a broader enterprise response architecture.

### EC2 Isolation

EventBridge routes supported HIGH or CRITICAL GuardDuty EC2 command-and-control findings imported through Security Hub to the EC2 containment state machine.

The workflow:

1. Enriches the finding with EC2 context.
2. Notifies the security team.
3. Initiates EBS snapshots to support investigation and preservation.
4. Creates or reuses a restrictive quarantine security group.
5. Replaces the instance security groups with the quarantine group.
6. Evaluates the isolation result.
7. Escalates partial or failed containment.
8. Writes structured execution evidence to S3.

The implemented action is security-group-based network containment.

It should not be interpreted as proof that every possible communication path associated with a workload has been removed.

---

## Security Architecture Decisions

### Qualify Findings Before Automation

Not every finding is allowed to initiate privileged remediation.

EventBridge rules restrict automated routing to supported finding types that meet defined severity, record-state, and workflow-status conditions.

This creates a control point between detection and automated action.

### Separate Orchestration from Containment

EventBridge receives permission to start the appropriate Step Functions workflow.

Step Functions coordinates the response and invokes the required Lambda functions.

The orchestration layer does not need to directly perform the IAM or EC2 containment operations.

Those permissions remain with the specialized response functions.

### Separate Automation Responsibilities

Notification, enrichment, IAM remediation, EC2 isolation, and audit writing are separated into different Lambda responsibilities rather than operating through one general-purpose remediation function.

This reduces the amount of privileged authority that must be assigned to each automation component.

### Treat Failure Paths as Security Decisions

The workflows explicitly handle retries, exceptions, partial results, escalation, and audit failures.

A notification failure, for example, does not automatically prevent containment from proceeding.

That reflects a security tradeoff: failure to send an alert should not necessarily leave a supported threat uncontained.

Other failures can require escalation or cause the workflow to terminate.

### Preserve Human Escalation

Automation is not treated as a replacement for incident-response personnel.

Partial and failed responses are surfaced to security operations for review and manual action.

The project implements escalation paths but does not implement a formal enterprise approval system for automated containment.

### Separate Containment from Recovery

The implemented playbooks focus on containment.

They do not automatically restore quarantined identities or workloads.

A production design would need explicit authority and procedures for actions such as restoring previous security groups, removing deny policies, re-enabling credentials, or releasing a workload from quarantine.

---

## Trust and Authority

The most important trust transition in this architecture occurs when a security finding becomes authority to modify an AWS resource.

The progression is:

```text
Detection
    |
    v
Finding Qualification
    |
    v
Orchestration
    |
    v
Privileged Containment
    |
    v
Evidence
    |
    v
Human Escalation When Required
```

Regional services and security findings are not themselves containment authority.

EventBridge determines which supported findings enter automated response.

Step Functions determines how the response proceeds.

Specialized Lambda identities receive the permissions necessary to perform specific actions.

Human operators retain responsibility for situations outside the implemented playbooks.

See [Trust and Authority in Automated Security Response](docs/trust-boundaries.md) for the detailed boundary analysis.

---

## Audit Evidence

Each response workflow can produce a structured S3 execution artifact containing available information such as:

* Finding context.
* Enrichment information.
* Response results.
* Notification information.
* Execution metadata.

This supports incident review and evidence collection without requiring the organization to reconstruct the entire response solely from individual service logs.

Step Functions and Lambda also generate operational logs, while CloudTrail provides AWS API activity records.

Evidence generation is therefore part of the response architecture rather than an after-the-fact activity.

---

## Logging, Retention, and Lifecycle

The project uses CloudTrail with a versioned S3 audit bucket.

The same storage architecture also supports SOAR execution artifacts and GuardDuty findings export.

During implementation, this design exposed an operational issue.

A large number of retained S3 object versions and delete markers accumulated in the versioned bucket. Although the bucket could appear empty through a normal object view, retained versions prevented Terraform from deleting the bucket successfully.

The problem demonstrated that security retention controls also have operational consequences.

The architecture was updated to include explicit lifecycle handling for current and noncurrent object versions, and the existing retained-object backlog was addressed through batched cleanup.

This resulted in an important architecture lesson:

> A security control can create operational and cost risk when its lifecycle behavior is not designed alongside the control itself.

Retention, recoverability, cost, and infrastructure lifecycle are therefore treated as related architecture decisions.

---

## Failure and Escalation Behavior

The Step Functions workflows do not treat every failure identically.

Examples include:

**Enrichment failure**

The workflow escalates because sufficient trusted context may not be available for the intended automated response.

**Notification failure**

Available execution context is recorded and containment can continue.

**Partial containment**

The workflow notifies security operations that manual completion is required.

**Containment failure**

The workflow escalates the incident for manual response.

**Audit artifact failure**

The workflow surfaces the evidence failure because the organization may need to rely on Step Functions, CloudWatch, and other available records to reconstruct the execution.

This makes failure behavior part of the security design rather than generic application exception handling.

---

## Testing and Validation

The repository includes:

```text
tests/trigger_findings.sh
```

The script supports:

* Generating GuardDuty IAM sample findings.
* Generating GuardDuty EC2 sample findings.
* Monitoring Step Functions executions.
* Validating deployed SOAR components.
* Inspecting generated S3 execution artifacts.

The script provides a repeatable way to exercise and inspect the architecture.

It is not presented as a complete automated security test suite.

---

## Infrastructure as Code

Terraform provisions the major architecture components through separate modules:

* GuardDuty.
* Security Hub.
* EventBridge.
* Step Functions.
* Lambda.
* IAM.
* SNS.
* CloudTrail and centralized logging.
* S3 audit storage.
* KMS encryption.

The modular structure separates major architectural responsibilities while allowing Terraform to manage the overall system as one infrastructure deployment.

---

## Repository Documentation

Supporting material is maintained under `docs/`:

* [Business Context](docs/business.md)
* [Technologies](docs/technologies.md)
* [Trust and Authority](docs/trust-boundaries.md)
* [Threat Model](docs/threat_model.md)
* [Design Decisions](docs/design_decisions.md)
* [Operational Runbook](docs/operational_runbook.md)
* [Compliance Mapping](docs/compliance_mapping.md)
* [Limitations](docs/limitations.md)
* [Lessons Learned](docs/lessonslearned.md)
* [Cost Analysis](docs/cost_analysis.md)
* [Scripts](docs/scripts.md)

An additional business-focused project analysis is available in the [Executive Case Study](EXECUTIVE_CASE_STUDY.md).

---

## Implemented Scope

The project implements:

* GuardDuty threat detection.
* Security Hub finding integration.
* EventBridge filtering and routing for selected findings.
* Step Functions IAM and EC2 response playbooks.
* Finding enrichment.
* SNS-based security notification.
* IAM user containment.
* EC2 security-group-based containment.
* EBS snapshot initiation during EC2 response.
* Partial and failed-response escalation.
* Structured S3 execution artifacts.
* CloudWatch workflow and Lambda logging.
* CloudTrail audit logging.
* Versioned S3 audit storage.
* KMS encryption for GuardDuty findings export.
* Terraform-based infrastructure deployment.

---

## Production Considerations

This is a portfolio architecture and automation implementation rather than a production enterprise SOAR platform.

A production design would require additional decisions around:

* Multi-account and multi-region response.
* Organization-level GuardDuty and Security Hub administration.
* Federated and IAM Identity Center session containment.
* Approval requirements for high-impact automated actions.
* Business-critical workload exceptions.
* False-positive handling.
* Recovery and containment reversal.
* Privileged automation-role monitoring.
* SIEM and incident-management integration.
* Evidence-retention requirements.
* Playbook change control.
* Emergency disablement of automated response.
* Expanded testing and failure injection.
* Operational ownership.
* Response and recovery SLOs.

These are architecture and governance decisions rather than capabilities implied by the current implementation.

---

## Executive Case Study

The [Executive Case Study](EXECUTIVE_CASE_STUDY.md) examines the project from a business and risk perspective, including the tradeoffs between:

* Response speed and business disruption.
* Automation and human control.
* Security evidence and storage cost.
* Retention and infrastructure operability.

It also documents how the S3 lifecycle issue discovered during implementation resulted in an architecture change rather than being treated solely as a Terraform cleanup problem.

---

## Key Takeaway

The value of SOAR is not simply that a Lambda function can modify a compromised resource.

The security architecture has to control the complete transition:

```text
Detect → Qualify → Orchestrate → Contain → Verify → Escalate → Preserve Evidence
```

The more authority automation receives, the more important identity separation, explicit failure behavior, auditability, recovery planning, and human governance become.

This project demonstrates that automated security response is itself a privileged security system and should be architected accordingly.
