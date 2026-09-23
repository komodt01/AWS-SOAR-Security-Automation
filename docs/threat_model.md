# Threat Model — Audit Evidence Pipeline

## Scope

This threat model focuses specifically on the audit evidence and logging path used by the SOAR architecture.

The primary flow evaluated here is:

```text
AWS API Activity
      |
      v
CloudTrail
      |
      v
Versioned S3 Audit Storage
      |
      +--> Retention / Lifecycle
      |
      +--> Authorized Evidence Access
```

The S3 storage architecture also supports SOAR execution artifacts and GuardDuty findings export.

This document does **not** attempt to threat-model the entire automated response platform.

Risks associated with finding qualification, orchestration, privileged remediation, IAM containment, EC2 isolation, human escalation, and recovery authority are addressed separately in [Trust and Authority in Automated Security Response](trust-boundaries.md).

The purpose of this analysis is narrower:

**Can the organization preserve trustworthy security evidence without creating unacceptable integrity, access, availability, lifecycle, or operational risk?**

---

## Assets Being Protected

The evidence pipeline protects information used to reconstruct and review security activity.

Important assets include:

* CloudTrail audit records.
* SOAR execution artifacts.
* GuardDuty findings exports.
* Historical object versions.
* Evidence metadata.
* Access to retained security records.

The security value of these assets depends on more than their existence.

They must remain sufficiently protected against unauthorized modification, deletion, disclosure, and loss while remaining operationally manageable.

---

## Trust Assumptions

This implementation relies on several AWS control-plane and identity assumptions.

CloudTrail is trusted to generate AWS API activity records.

S3 is trusted to enforce configured storage, versioning, encryption, access, and lifecycle controls.

IAM policies and service roles are trusted to restrict access to the evidence path.

KMS is used for GuardDuty findings-export encryption.

These controls reduce risk, but none removes the need to govern the identities that can change logging, storage, lifecycle, encryption, or access policies.

An identity capable of changing the evidence controls may have a different risk profile from an identity that can only read the resulting evidence.

---

## STRIDE Analysis

### Spoofing

#### Threat

An unauthorized principal could attempt to impersonate a trusted user, service, or automation component to gain access to security evidence or interact with the logging environment.

The risk is especially important for privileged identities capable of modifying:

* CloudTrail configuration.
* S3 bucket policies.
* Lifecycle configuration.
* Evidence access permissions.
* Encryption configuration.

#### Implemented Controls

The architecture uses AWS IAM roles and policies to control service and workload access.

CloudTrail, S3, and other AWS services operate through defined AWS service identities and permissions.

Access to evidence therefore depends on authenticated AWS identities rather than anonymous application access.

#### Residual Risk

Compromise of an authorized AWS identity could allow an attacker to operate with that identity's legitimate permissions.

Authentication alone therefore does not establish that an action is trustworthy.

Production environments should place additional governance around privileged identities capable of modifying the evidence pipeline.

---

### Tampering

#### Threat

An attacker or overly privileged administrator could attempt to alter, replace, or delete evidence to make investigation more difficult.

Tampering could target:

* Audit records.
* SOAR execution artifacts.
* Bucket configuration.
* Object versions.
* Lifecycle rules.
* Logging configuration.

#### Implemented Controls

S3 Versioning retains object versions rather than treating every overwrite or deletion as immediate permanent removal.

CloudTrail records AWS API activity that can assist with reconstruction of administrative changes.

Access is governed through AWS IAM and S3 permissions.

These controls improve recoverability and visibility, but versioning should not be interpreted as making evidence immutable.

#### Residual Risk

An identity with sufficient S3, IAM, or administrative authority may still be able to alter evidence-related configuration or delete retained versions.

Production environments requiring stronger evidence immutability could evaluate additional controls such as:

* S3 Object Lock.
* Dedicated security logging accounts.
* Cross-account evidence storage.
* Tighter separation of logging administration from workload administration.
* Independent monitoring of logging configuration changes.

Those controls are production considerations and are not claimed as implemented by this project.

---

### Repudiation

#### Threat

A user, administrator, or automated component could deny performing an action relevant to a security incident.

This becomes particularly important when the SOAR platform itself performs privileged containment actions.

#### Implemented Controls

CloudTrail records AWS API activity and associated execution context.

The SOAR workflows also generate structured execution artifacts containing available response information.

Step Functions and Lambda provide additional execution and operational records.

Together, these sources improve the organization's ability to reconstruct what occurred.

#### Residual Risk

CloudTrail and workflow records provide audit evidence, but this project does not claim that every action is cryptographically non-repudiable.

Evidence quality still depends on:

* Logging coverage.
* Retention.
* Identity integrity.
* Time and event correlation.
* Protection of stored records.
* Availability of relevant service logs.

The architecture therefore treats auditability as an evidence problem rather than assuming that the existence of CloudTrail alone eliminates repudiation risk.

---

### Information Disclosure

#### Threat

Security evidence can contain sensitive operational information.

Depending on the event, retained records may reveal:

* AWS resource identifiers.
* Identity information.
* API activity.
* Security findings.
* Response actions.
* Infrastructure details.
* Incident context.

Unauthorized disclosure could provide an attacker with information useful for reconnaissance or further compromise.

#### Implemented Controls

Access to the evidence environment is governed through AWS IAM and S3 permissions.

GuardDuty findings export uses KMS encryption.

AWS service communication uses AWS-supported encrypted transport.

#### Residual Risk

Encryption does not prevent disclosure to an identity that is legitimately authorized but overly privileged.

Evidence access should therefore follow least privilege.

Production environments should also determine:

* Which security teams require read access.
* Which administrators can change evidence controls.
* Whether incident evidence requires separate storage.
* How long sensitive records should remain accessible.
* Whether cross-account evidence access is appropriate.

---

### Denial of Service and Evidence Availability

#### Threat

The evidence pipeline can become unavailable or operationally impaired even without a traditional service outage.

Possible conditions include:

* Logging being disabled.
* Evidence writes failing.
* Permission changes blocking access.
* Storage growth creating operational problems.
* Lifecycle configuration removing records too early.
* Retained versions preventing expected infrastructure teardown.

Evidence availability therefore includes both the ability to write records and the ability to retrieve and manage them later.

#### Implemented Controls

The SOAR workflows surface audit-artifact failures so evidence-generation problems are visible rather than silently ignored.

S3 Versioning provides protection against some accidental overwrites and deletions.

Lifecycle handling has been added for current and noncurrent object versions.

#### Operational Finding

This project encountered an actual lifecycle failure mode.

More than 145,000 current and noncurrent objects accumulated in the versioned S3 environment.

Retained versions and delete markers prevented Terraform from deleting the bucket during teardown.

The incident demonstrated that retention controls can create an availability and operability problem of their own.

The response included:

* Batched cleanup of retained versions and delete markers.
* Explicit lifecycle handling for current objects.
* Explicit lifecycle handling for noncurrent versions.
* Recognition of lifecycle behavior as an architecture concern rather than only a cleanup task.

#### Residual Risk

Production environments would still require monitoring for:

* Storage growth.
* Version accumulation.
* Lifecycle-policy changes.
* Logging failures.
* Unexpected evidence deletion.
* Retention-policy violations.
* Cost anomalies.

Security evidence must remain available long enough to satisfy investigation and governance requirements without creating uncontrolled storage or lifecycle risk.

---

### Elevation of Privilege

#### Threat

An identity with excessive permissions over the evidence environment could move from normal operational access to control over logging or retained evidence.

Particularly sensitive permissions include the ability to:

* Change CloudTrail configuration.
* Modify S3 bucket policies.
* Modify lifecycle rules.
* Delete object versions.
* Change IAM permissions.
* Change encryption configuration.

The concern is not only who can read evidence.

It is who can change the controls that determine whether evidence exists and remains trustworthy.

#### Implemented Controls

The project uses IAM roles and policies to assign service and automation permissions.

SOAR functions are separated by responsibility rather than operating under one universal execution identity.

That separation reduces unnecessary sharing of authority across automation components.

#### Residual Risk

This portfolio implementation does not represent a complete enterprise separation-of-duties model.

A production architecture could further separate:

```text
Workload Administration
          |
          X
          |
Security Logging Administration
          |
          X
          |
Evidence Review / Investigation
```

The objective would be to prevent one operational identity from having unnecessary control over workloads, evidence configuration, and evidence review.

---

## Evidence Integrity Versus Evidence Retention

One of the key lessons from this project is that integrity and retention controls can create competing operational concerns.

Longer retention and versioning can improve:

* Recoverability.
* Investigation depth.
* Historical evidence.
* Protection against accidental deletion.

The same controls can increase:

* Storage consumption.
* Cost.
* Cleanup complexity.
* Infrastructure teardown complexity.
* Administrative burden.

The architecture therefore does not treat maximum retention as automatically equivalent to maximum security.

Retention should be based on investigation, regulatory, business, and operational requirements.

---

## Shared Storage Consideration

The implemented storage architecture supports multiple security-related evidence types, including CloudTrail records, SOAR execution artifacts, and GuardDuty findings export.

This simplifies the portfolio implementation but creates a shared security boundary.

A configuration error, access-policy issue, lifecycle problem, or storage failure can therefore affect more than one evidence source.

A larger enterprise implementation could evaluate whether different evidence classes should use:

* Separate buckets.
* Separate AWS accounts.
* Different retention periods.
* Different access policies.
* Different encryption keys.
* Different immutability requirements.

Those decisions depend on organizational risk and compliance requirements and are not implemented here.

---

## Detection and Response to Evidence Problems

Evidence controls should themselves be observable.

Important conditions for a production environment would include detection of:

* CloudTrail being disabled or modified.
* Bucket-policy changes.
* Lifecycle-policy changes.
* Unexpected version deletion.
* KMS-policy changes.
* Failed evidence writes.
* Abnormal storage growth.
* Unexpected evidence access.

This project provides logging and workflow visibility but does not claim to implement a complete monitoring program for every evidence-control change.

---

## Threat Model Outcome

The audit pipeline demonstrates a broader security architecture principle:

**Evidence is itself a protected security asset.**

Creating logs is not enough.

The organization must also control:

```text
Who can create evidence
        |
Who can access evidence
        |
Who can change evidence controls
        |
How long evidence is retained
        |
How evidence is protected from alteration
        |
How evidence remains operationally manageable
```

The implemented architecture provides versioned storage, access controls, encryption for GuardDuty findings export, CloudTrail auditing, SOAR execution artifacts, and lifecycle handling.

A production implementation would extend those controls based on the required level of immutability, administrative separation, retention, monitoring, and cross-account protection.

The lifecycle issue encountered during this project reinforces the central lesson:

**Security evidence must be designed for integrity, availability, governance, and lifecycle—not simply collection.**
