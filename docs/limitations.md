# Limitations

This project demonstrates selected SOAR architecture and automated-response patterns in AWS.

It is not intended to represent a complete enterprise incident-response platform.

The following limitations define the current implementation boundary.

## Automated Response Scope

The project implements two primary automated-response scenarios:

* IAM user credential compromise.
* EC2 network containment.

EventBridge routes selected HIGH and CRITICAL GuardDuty findings imported through Security Hub into these workflows.

Other GuardDuty and Security Hub finding types are not automatically remediated by the implemented playbooks.

A production SOAR capability would require broader playbook coverage based on organizational threat models, resource criticality, and incident-response procedures.

## IAM Containment Scope

The IAM workflow is designed around affected IAM users.

Implemented containment can:

* Disable active IAM user access keys.
* Apply an emergency explicit-deny policy.
* Tag the affected IAM user for quarantine.

This does not provide universal AWS identity containment.

The implementation does not claim to revoke unrelated:

* Federated sessions.
* IAM Identity Center sessions.
* Assumed-role sessions.

Those identity paths would require additional response mechanisms.

## EC2 Isolation Scope

EC2 containment is implemented primarily through security-group replacement.

The workflow can also initiate EBS snapshots to support investigation and preservation.

Replacing security groups restricts network paths controlled by those security groups, but it should not be interpreted as guaranteed isolation from every possible communication or control path.

Production containment could require additional controls depending on workload architecture, routing, attached services, identity permissions, and incident severity.

## Automated Containment Does Not Require Pre-Approval

Supported findings can initiate the implemented containment workflows automatically.

The project does not implement a formal human approval gate before containment.

Partial and failed actions are escalated to security operations.

An enterprise deployment would need to determine whether some identities, workloads, environments, or business-critical resources require approval before automated containment.

## Recovery Is Not Automated

The implemented workflows focus on containment rather than restoration.

The project does not automatically:

* Re-enable IAM credentials.
* Remove emergency deny policies.
* Restore previous EC2 security groups.
* Release quarantined resources.
* Validate that an affected resource is safe to return to service.

Production recovery would require defined ownership, authorization, validation, and rollback procedures.

## Evidence Storage Uses a Shared Security Boundary

CloudTrail records, SOAR execution artifacts, and GuardDuty findings export use the project's security logging and storage architecture.

This simplifies the implementation but creates a shared storage boundary.

A lifecycle, access-policy, encryption, or availability issue could therefore affect multiple evidence sources.

A larger enterprise implementation could separate evidence classes by bucket, AWS account, retention policy, access model, or encryption boundary.

## Evidence Is Versioned, Not Immutable

S3 Versioning improves recoverability from accidental overwrites and deletions.

It does not make the evidence store immutable.

An identity with sufficient permissions could still modify storage configuration or delete retained versions.

Production environments with stronger forensic or regulatory requirements could evaluate controls such as:

* S3 Object Lock.
* Dedicated security logging accounts.
* Cross-account evidence storage.
* Stronger administrative separation.
* Independent monitoring of evidence-control changes.

These controls are not implemented in this project.

## S3 Lifecycle Management

The project previously encountered a significant lifecycle issue with the versioned audit bucket.

More than 145,000 current and noncurrent objects accumulated, and retained object versions and delete markers prevented Terraform from deleting the bucket during teardown.

The current architecture includes explicit lifecycle handling for current objects and noncurrent versions.

The historical backlog required batched cleanup.

This means the original limitation was not that versioned S3 storage could never be managed through infrastructure lifecycle controls. The issue was that retention behavior had not originally been designed alongside teardown and cost management.

Lifecycle configuration reduces this risk but does not eliminate the need to monitor:

* Storage growth.
* Version accumulation.
* Retention requirements.
* Lifecycle-policy changes.
* Cost.
* Evidence availability.

## Response Authority Exists Within the AWS Environment

The automated remediation functions require privileged AWS permissions to perform containment.

Separate Lambda responsibilities and IAM roles reduce unnecessary privilege sharing, but the project is not a complete enterprise separation-of-duties implementation.

A production architecture could further separate:

* Security tooling administration.
* Workload administration.
* Logging administration.
* Incident investigation.
* Playbook deployment authority.
* Containment authority.

Multi-account security administration would also change where these authorities reside.

## Multi-Account and Multi-Region Response

The project demonstrates the response architecture within its implemented AWS environment.

It does not implement an organization-wide multi-account or multi-region SOAR operating model.

A production design could require:

* Delegated GuardDuty administration.
* Delegated Security Hub administration.
* Cross-account remediation roles.
* Regional response orchestration.
* Central security tooling accounts.
* Account-specific containment policies.

Those decisions would depend on the organization's AWS operating model.

## SIEM and Incident-Management Integration

SNS provides notification and escalation capability within the project.

The implementation does not represent a complete integration with an enterprise:

* SIEM.
* SOAR platform.
* ITSM system.
* Case-management platform.
* On-call management system.

Production response would normally require incident ownership and case tracking beyond an individual automated workflow.

## Testing Scope

The repository includes a script for generating GuardDuty sample findings and observing the resulting response workflows.

This provides repeatable architecture validation.

It is not a complete automated test suite.

Additional production testing could include:

* Negative tests.
* Permission-failure tests.
* Partial-remediation scenarios.
* Evidence-write failures.
* Notification failures.
* Idempotency testing.
* False-positive scenarios.
* Recovery testing.
* Failure injection.
* Multi-account response testing.

## Operational Ownership

The project demonstrates technical response behavior but does not define a complete enterprise operating model.

Production deployment would require explicit ownership for:

* Detection rules.
* Playbooks.
* IAM permissions.
* Exception handling.
* Incident escalation.
* Recovery.
* Evidence retention.
* Lifecycle management.
* Service monitoring.
* Change approval.

## Summary

The project demonstrates how AWS security findings can move through qualification, orchestration, containment, escalation, and evidence preservation.

Its primary limitation is not the absence of automation.

It is that enterprise SOAR requires governance around the authority automation receives.

The implemented project establishes the core architecture patterns, while broader identity coverage, recovery, multi-account operation, approval workflows, immutable evidence, enterprise integrations, and operational governance remain production considerations.
