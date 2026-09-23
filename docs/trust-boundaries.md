# Trust and Authority in Automated Security Response

## Why Authority Matters in SOAR

A security finding begins as information.

A containment action changes the environment.

The important security transition in this architecture occurs when the system moves from observing a threat to receiving authority to modify IAM identities or EC2 resources.

The implemented response path is:

```text
GuardDuty
    |
Security Hub
    |
EventBridge
    |
Step Functions
    |
    +--> Enrichment
    +--> Notification
    +--> IAM or EC2 Containment
    +--> Audit Evidence
    |
Human Escalation When Required
```

Each transition changes what the automation is trusted to do.

The architecture therefore treats automated response itself as a privileged security capability.

## 1. From Detection to Actionable Finding

GuardDuty generates security findings that are imported into Security Hub.

At this point, the system is still operating primarily in the detection domain.

A finding describes suspected security activity. It does not by itself have authority to modify the affected resource.

EventBridge is the transition point that determines which findings are allowed to enter an automated response workflow.

The implemented rules restrict routing to active, new GuardDuty findings with HIGH or CRITICAL severity and supported finding types.

For IAM response, the rule targets supported IAM unauthorized-access findings.

For EC2 response, the rule targets supported command-and-control findings.

This creates an important control:

```text
Security Finding
      |
      |  EventBridge selection criteria
      v
Approved Automated Playbook
```

Not every security finding receives containment authority.

The routing policy determines which detected conditions are permitted to trigger automation.

## 2. From Routing to Orchestration

EventBridge does not directly perform containment.

Its execution role is permitted to start the defined Step Functions state machines.

This separates event selection from response execution.

The EventBridge role therefore needs authority to initiate the workflow, but it does not need the IAM or EC2 permissions used by the containment functions themselves.

Step Functions becomes the orchestration boundary.

It determines:

* Which Lambda function executes next.
* Whether an operation is retried.
* Whether a partial result requires escalation.
* Whether a failure stops or redirects the workflow.
* When execution evidence should be written.

The Step Functions execution role can invoke the Lambda functions participating in the playbooks.

It does not need to directly disable IAM credentials or modify EC2 security groups because those permissions belong to the response functions.

This keeps orchestration authority separate from containment authority.

## 3. The Point Where Automation Gains Containment Authority

The highest-risk transition occurs when Step Functions invokes a remediation Lambda.

Before this point, the architecture has primarily detected, routed, enriched, and communicated information.

After this point, the system can change the security state of AWS resources.

The IAM and EC2 playbooks cross that boundary differently.

### IAM Containment

For supported IAM user findings, the remediation function can perform actions including:

* Disabling active access keys.
* Applying an emergency explicit-deny policy.
* Tagging the affected IAM user to indicate quarantine status.

Conceptually:

```text
Finding
   |
Enrichment
   |
IAM Remediation Function
   |
   +--> Access Keys
   +--> Emergency Deny Policy
   +--> Quarantine Tag
```

The function is intentionally scoped to the affected IAM user.

This does not represent universal identity containment.

The project does not claim to revoke unrelated:

* Federated sessions.
* IAM Identity Center sessions.
* Assumed-role sessions.

That distinction matters because disabling an IAM user's access keys is not equivalent to invalidating every possible AWS session associated with a person or workload.

### EC2 Containment

The EC2 response function receives a different set of privileges.

For supported EC2 findings, it can:

* Tag the instance for quarantine.
* Initiate EBS snapshots.
* Create or reuse a restrictive quarantine security group.
* Replace the instance's existing security groups with the quarantine group.

Conceptually:

```text
Affected EC2 Instance
        |
        +--> Preserve EBS state
        |
        +--> Replace network security groups
        |
        +--> Record quarantine state
```

This is network containment implemented through security-group changes.

It should not be interpreted as guaranteed isolation from every possible communication path.

Other network controls, attached services, identity permissions, or architecture-specific connectivity could require additional response actions in a production environment.

## 4. Separate Identities Limit the Automation Blast Radius

The architecture does not place notification, enrichment, remediation, and evidence-writing authority into one general-purpose Lambda execution role.

Different functions receive permissions based on their responsibilities.

That separation matters because compromise or malfunction of a notification function should not automatically provide the same authority as the IAM or EC2 containment functions.

The intended authority model is closer to:

```text
Notification Function
    |
    +--> Notification Authority

Enrichment Function
    |
    +--> Read / Context Authority

IAM Remediation Function
    |
    +--> IAM Containment Authority

EC2 Isolation Function
    |
    +--> EC2 Containment Authority

Audit Function
    |
    +--> Evidence-Writing Authority
```

Least privilege in this architecture therefore applies not only to individual AWS API permissions but also to the separation of operational responsibilities between automation components.

## 5. Failure Does Not Automatically Mean Stop

Security automation has an unusual failure problem.

Stopping immediately may be safer for some operations.

For others, stopping could leave a compromised resource active.

The Step Functions workflows therefore contain explicit failure paths rather than treating every exception identically.

For example, notification failure does not necessarily prevent containment from continuing.

That represents a deliberate tradeoff:

```text
Notification Failed
       |
       v
Record Available Context
       |
       v
Continue Containment
```

The rationale is that failure to notify an analyst should not automatically leave a supported threat uncontained.

Other failures produce different outcomes.

Enrichment failure is escalated because the workflow may no longer have sufficient trusted context for the intended response.

Partial or failed containment is escalated because the automated security objective was not fully achieved.

Audit-writing failure is also surfaced because loss of response evidence affects the ability to reconstruct and review the incident.

The failure path is therefore part of the security policy, not merely application error handling.

## 6. Evidence Is a Separate Security Boundary

Containment changes the environment.

The organization must also be able to determine what the automation did.

The workflow writes structured execution artifacts containing response context to S3.

Step Functions and Lambda activity is additionally observable through their logging mechanisms, while CloudTrail provides AWS API activity records.

This creates a separation between:

```text
Response Authority
       |
       v
Resource Change

and

Evidence Authority
       |
       v
Execution Record
```

The function responsible for writing execution evidence does not need the same containment authority as the functions changing IAM or EC2 resources.

That distinction reduces the need to combine investigative evidence handling with privileged remediation capability.

Evidence storage introduces its own security and lifecycle concerns.

Versioning and retention can improve recoverability and forensic value, but they also create storage, cost, and deletion implications. This project encountered that tradeoff directly when retained S3 versions complicated infrastructure teardown.

Evidence protection and evidence lifecycle therefore need to be designed together.

## 7. Human Authority Remains Outside the Automated Workflow

The architecture does not assume that automation can resolve every incident.

Partial and failed responses are escalated to security operations.

This creates an intentional transition from machine authority back to human decision-making.

```text
Automated Response
       |
       +--> SUCCESS --> Record Evidence
       |
       +--> PARTIAL --> Analyst Review
       |
       +--> FAILURE --> Analyst Intervention
```

The analyst becomes responsible for determining actions that fall outside the implemented playbook.

Examples can include:

* Completing containment manually.
* Investigating unsupported identity sessions.
* Evaluating business impact.
* Coordinating workload recovery.
* Determining whether quarantine should be reversed.
* Expanding containment beyond the originally affected resource.

The implemented project provides notification and escalation paths.

It does not implement a formal enterprise approval system for containment decisions.

## 8. Recovery Is a Different Authority from Containment

The implemented workflows focus on containment.

Containment and recovery should not automatically be treated as the same authority.

A system that is permitted to quarantine an identity or workload does not necessarily need permission to restore it to production.

For a production implementation, organizations would need to decide who can:

* Re-enable credentials.
* Remove emergency deny policies.
* Restore previous EC2 security groups.
* Release quarantined workloads.
* Approve recovery.
* Validate that the original threat has been removed.

Separating containment from restoration can reduce the risk that the same compromised or malfunctioning automation both isolates and automatically re-enables a resource.

Those recovery controls are not implemented in this project.

## 9. Important Bypass and Failure Scenarios

Several conditions could weaken the intended response model.

### Unsupported Finding

A finding that does not match the EventBridge criteria does not enter these automated playbooks.

That is expected behavior, not necessarily a detection failure.

The automation covers selected response scenarios rather than every GuardDuty or Security Hub finding.

### Incorrect Finding Context

Automated containment depends on correctly identifying the affected resource.

Incorrect or incomplete context could cause the intended containment action to fail or create operational impact.

Enrichment and explicit workflow handling reduce this risk but do not eliminate the need for production safeguards.

### Excessive Remediation Permissions

If a remediation function receives broader permissions than required, compromise of that function increases the possible blast radius.

The containment identity is therefore one of the most sensitive identities in the architecture.

### Partial EC2 Isolation

Replacing security groups restricts network connectivity controlled by those security groups.

It does not prove that every possible communication or control path associated with the workload has been removed.

### Incomplete Identity Containment

Disabling IAM user access keys and applying a deny policy addresses the implemented IAM-user scenario.

Other identity mechanisms may require separate containment procedures.

### Evidence Failure

A containment action can succeed while evidence writing fails.

The resource may be safer while the organization's ability to reconstruct the response is weaker.

The workflow therefore treats evidence failure as an operational security condition requiring visibility.

## If This Became an Enterprise SOAR Capability

A production architecture would require governance around the authority granted to automation, not simply additional Lambda functions.

Key decisions would include:

* Which findings may trigger automatic containment.
* Which resource types may be modified automatically.
* Which business-critical resources require approval before containment.
* How false positives are handled.
* How automated actions are reversed safely.
* How privileged automation roles are reviewed and monitored.
* How multi-account and multi-region response authority is delegated.
* How federated and IAM Identity Center sessions are contained.
* How containment interacts with incident-management and SIEM platforms.
* How evidence retention is governed.
* How playbook changes are approved and deployed.
* How emergency disablement of the automation itself is performed.
* Who owns the service operationally.
* What response and recovery SLOs apply.

The central governance question is not:

**Can this response be automated?**

It is:

**What authority should automation receive, under what conditions, and where must that authority stop?**

## Architecture Takeaway

The primary trust boundary in a SOAR architecture is the transition from **security information to security authority**.

GuardDuty and Security Hub identify conditions.

EventBridge decides which supported conditions enter automated response.

Step Functions controls how the response proceeds.

Specialized Lambda identities receive the permissions necessary to perform defined containment actions.

Evidence mechanisms record what occurred.

Human escalation handles situations where automated authority is insufficient or the response does not complete as intended.

That separation allows automation to reduce response time without treating the automation platform as an unrestricted security administrator.
