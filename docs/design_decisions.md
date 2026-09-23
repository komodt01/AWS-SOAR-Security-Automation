# Design Decisions

## Security Evidence Retention and Lifecycle

### Context

The SOAR architecture generates and retains multiple forms of security evidence, including CloudTrail records, GuardDuty findings export, and structured response artifacts.

S3 Versioning was used to improve recoverability and preserve historical object versions.

During implementation, the versioned audit environment accumulated more than 145,000 current and noncurrent objects. Retained versions and delete markers eventually prevented Terraform from deleting the bucket during teardown.

The issue demonstrated that evidence retention cannot be designed independently from infrastructure lifecycle, operational cost, and recoverability.

### Decision

Retain versioned security evidence while explicitly managing both current and noncurrent object lifecycle.

The architecture was updated to include lifecycle handling rather than relying on versioning with indefinite accumulation.

The existing retained-object backlog was addressed separately through batched cleanup.

### Why

Removing versioning entirely would reduce the ability to recover from accidental overwrites or deletions.

Retaining every version indefinitely would increase storage growth and make infrastructure lifecycle increasingly difficult.

The chosen approach preserves the security benefit of versioning while placing boundaries around long-term retention.

### Tradeoff

Longer retention can improve:

* Investigation depth.
* Historical evidence.
* Recoverability.
* Protection against accidental deletion.

It can also increase:

* Storage cost.
* Version accumulation.
* Cleanup complexity.
* Teardown complexity.
* Administrative overhead.

The architecture therefore does not assume that maximum retention automatically provides maximum security.

### Operational Consequence

Lifecycle configuration reduces uncontrolled accumulation but does not eliminate the need to monitor:

* Storage growth.
* Version counts.
* Retention requirements.
* Lifecycle-policy changes.
* Evidence availability.
* Cost.

Retention periods should ultimately reflect organizational investigation, regulatory, legal, and operational requirements.

### Architecture Principle

**A security control must be designed for its full lifecycle, not only for the moment when it is enabled.**

Logging and versioning improve security visibility and recoverability, but their storage, retention, cost, and teardown behavior are part of the architecture as well.
