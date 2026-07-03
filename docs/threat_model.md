# Threat Model (STRIDE)

## Scope
This threat model covers the CloudTrail/S3 audit logging pipeline: 
log generation (CloudTrail) → storage (versioned S3 bucket) → 
retention (version lifecycle) → access (IAM-scoped read/write). Each 
STRIDE category below is evaluated against this flow.

## Spoofing
**Risk:** Unauthorized identity generating or injecting logs, undermining 
trust in the audit trail itself.
**Mitigation:** IAM authentication required for all CloudTrail-related 
actions; CloudTrail's own log file validation (digest files) used to 
detect tampering with the identity of the log source.

## Tampering
**Risk:** Logs altered or deleted after the fact, compromising forensic 
and compliance integrity.
**Mitigation:** S3 Versioning ensures no object is truly overwritten or 
deleted, prior versions remain recoverable. Note: this same control is 
what later created the teardown/cost issue below, an example of a 
security control introducing an operational tradeoff that has to be 
managed, not just accepted.

## Repudiation
**Risk:** Actors denying they performed a given action.
**Mitigation:** CloudTrail audit logs provide a non-repudiable record of 
API activity tied to IAM identity.

## Information Disclosure
**Risk:** Exposure of sensitive data contained in logs (IAM activity, 
resource configuration, potentially sensitive parameters).
**Mitigation:** Encryption at rest (SSE) and in transit, combined with 
least-privilege access controls restricting who can read the log bucket.

## Denial of Service (Cost / Storage)
**Risk:** Unbounded log and version growth degrading system performance 
or, more practically in this project, causing runaway storage cost and 
blocking infrastructure teardown. This is the threat category that 
manifested directly in this project: versioned S3 objects accumulated 
faster than they were being managed.
**Mitigation:** Lifecycle policies to expire noncurrent versions, cost 
monitoring at the resource level (not just account-level billing 
alarms), and teardown procedures that explicitly account for version 
history.

## Elevation of Privilege
**Risk:** Unauthorized access to logs enabling further reconnaissance 
or privilege escalation.
**Mitigation:** Least-privilege IAM policies scoping log access to only 
the roles/services that require it.
