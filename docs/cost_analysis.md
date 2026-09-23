# Cost Analysis

## Cost Risk

Security logging can create significant storage growth when event volume, versioning, and retention are considered together.

In this project, CloudTrail and other security evidence were stored in a versioned S3 environment.

Versioning preserves noncurrent object versions unless lifecycle controls explicitly manage them. As a result, storage consumption can be substantially larger than what is visible when reviewing only current objects.

The project eventually accumulated more than 145,000 current and noncurrent objects.

This created both a storage concern and an infrastructure lifecycle problem.

## Why the Risk Was Not Initially Obvious

The original design focused primarily on the security value of retaining audit evidence.

The operational consequences of version accumulation received less attention.

A normal view of an S3 bucket emphasizes current objects, while noncurrent versions and delete markers require explicit inspection.

This meant the true storage and lifecycle footprint was less visible until teardown exposed the problem.

The issue demonstrated that account-level cost visibility alone would not explain the architecture condition causing the growth.

Understanding the resource model itself is necessary.

## Cost and Architecture Relationship

The relevant cost model is not simply:

```text id="v1h31w"
Number of Current Objects
        x
Storage Cost
```

Versioned evidence introduces additional factors:

```text id="xw2xb7"
Event Volume
      |
      v
Current Objects
      +
Noncurrent Versions
      +
Retention Duration
      |
      v
Storage Consumption
      |
      +--> Cost
      |
      +--> Lifecycle Complexity
```

Retention architecture therefore affects both security and operating cost.

## Mitigation Implemented

The architecture was updated to include lifecycle handling for current and noncurrent objects rather than allowing versions to accumulate indefinitely.

The existing retained-object backlog was addressed through controlled batched cleanup.

These changes reduce uncontrolled storage growth while preserving the security benefit of versioned evidence.

## Ongoing Considerations

A production environment should evaluate:

* Security-event volume.
* Current and noncurrent object counts.
* Required evidence-retention periods.
* S3 storage classes.
* Lifecycle transitions.
* Expiration requirements.
* Investigation requirements.
* Regulatory or legal retention requirements.
* Cost associated with long-term evidence storage.
* Operational impact of eventual deletion or teardown.

Cost monitoring can identify increasing spend, but it does not replace architecture-level understanding of why resources are accumulating.

## Tradeoff

Shorter retention can reduce storage cost and lifecycle complexity.

Longer retention can improve investigation depth, historical visibility, and recoverability.

Neither extreme is automatically correct.

Retention should reflect the organization's security, investigation, regulatory, legal, and operational requirements.

## Architectural Principle

**Cost is an architecture input, not simply a billing outcome.**

Security controls consume resources over time.

Logging, evidence preservation, encryption, versioning, and retention should therefore be evaluated not only for the protection they provide, but also for how they behave at scale.

The lesson from this project is that sustainable security architecture requires understanding both the control and its long-term operational footprint.
