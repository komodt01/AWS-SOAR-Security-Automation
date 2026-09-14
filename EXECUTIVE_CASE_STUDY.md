# Executive Case Study — AWS SOAR Security Automation

## Executive Summary

Security automation can reduce incident-response time, but it also introduces
new operational and business risks.

This project explores an AWS Security Orchestration, Automation, and Response
(SOAR) architecture designed to automate selected IAM and EC2 containment
actions while maintaining analyst visibility, controlled permissions, failure
handling, and audit evidence.

During implementation, the supporting audit architecture also exposed an
unexpected operational issue: security logging and S3 versioning created a
large volume of retained data that eventually prevented automated
infrastructure teardown.

The experience reinforced an important architecture principle:

> Security controls must be designed not only for protection and compliance,
> but also for lifecycle, cost, operational impact, and recoverability.

---

## Business Problem

Security teams need to respond quickly when cloud threats are detected.

Manual investigation and containment can increase the time between detection
and response, particularly when analysts must gather resource context and
perform repetitive containment actions.

Automation can shorten that process, but aggressive automation introduces its
own risks.

A poorly controlled response could:

- Disable legitimate access.
- Interrupt a business-critical workload.
- Perform actions with excessive privileges.
- Fail without alerting an analyst.
- Leave incomplete evidence of what occurred.

The architecture therefore needed to balance response speed with control and
accountability.

---

## Architecture Approach

I designed the solution around two automated response scenarios:

- IAM credential compromise
- EC2 workload isolation

AWS security findings are routed into orchestrated response workflows that
enrich the finding, notify security operations, perform defined containment
actions, evaluate the result, escalate when necessary, and retain an execution
record.

Rather than treating automation as a replacement for security operations, I
designed it as a controlled extension of the incident-response process.

Human escalation remains part of the architecture when automated containment
is incomplete or unsuccessful.

---

## Key Architecture Decisions

### Limit the Authority of Automation

Response functions use separate permissions based on their responsibilities
rather than operating under one broadly privileged automation identity.

The objective is to reduce the potential blast radius if an automation
component behaves incorrectly or is compromised.

### Preserve Human Oversight

Partial and failed responses are surfaced for analyst review.

In a production environment, higher-impact containment actions could also
require approval based on workload criticality and organizational risk
tolerance.

### Build Auditability into the Response

The workflow creates structured execution artifacts that can support incident
review, operational analysis, and evidence collection.

This makes evidence generation part of the response process instead of
requiring the organization to reconstruct the sequence of events afterward.

---

## Operational Issue Discovered

The project's audit architecture used CloudTrail and a versioned S3 bucket to
preserve security activity.

During development, the bucket accumulated more than 145,000 current and
noncurrent objects.

When the environment was later torn down through Terraform, retained object
versions and delete markers prevented the bucket from being deleted.

What initially appeared to be a Terraform problem was actually a lifecycle
design problem.

The logging control had been considered primarily from the perspective of
security and retention. Its long-term storage behavior, teardown impact, and
operational cost had not been given equal consideration.

---

## Architecture Response

The immediate retained-object backlog was addressed through batched cleanup.

The architecture was then changed to explicitly manage both current and
noncurrent object retention rather than relying on versioning without a
complete lifecycle strategy.

Logging scope was also reviewed to reduce unnecessary data-event collection.

The important outcome was not simply getting Terraform teardown to work
again. The design itself changed based on what the operational failure
revealed.

---

## Business and Risk Impact

The project highlighted several tradeoffs that security architects need to
consider.

**Faster response vs. business disruption**

Automated containment can reduce exposure time, but an incorrect action can
interrupt legitimate access or workloads.

**Security evidence vs. cost**

Audit data is valuable, but indefinite or poorly understood retention can
create unnecessary storage and operational expense.

**Automation vs. control**

Automation can improve consistency and response speed, but the automation
itself becomes a privileged part of the security architecture and must be
governed accordingly.

**Retention vs. operability**

Controls intended to preserve evidence can interfere with infrastructure
lifecycle and recovery if deletion and retention behavior are not explicitly
designed.

---

## Production Considerations

For an enterprise implementation, I would expect additional decisions around:

- Which containment actions can execute automatically
- Which actions require analyst approval
- Business-critical workload exceptions
- Multi-account and multi-region response
- Federated identity containment
- SIEM and incident-management integration
- Evidence-retention requirements
- Recovery from incorrect containment
- Operational ownership and response SLOs
- Cost monitoring and lifecycle governance

These decisions would need to reflect the organization's risk tolerance,
regulatory requirements, workload criticality, and incident-response model.

---

## Outcome

The project produced an event-driven AWS security-response architecture that
connects detection, enrichment, containment, escalation, and evidence
generation.

More importantly, implementation exposed an operational weakness in the
original audit-retention design and resulted in an architectural correction.

The broader lesson is that a security architecture should not be judged only
by whether its controls work.

A successful design also has to account for how those controls affect the
business over time — including operations, cost, availability, recovery, and
the people responsible for running the environment.
