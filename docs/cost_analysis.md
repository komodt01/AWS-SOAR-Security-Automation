# Cost Analysis

## Risk
CloudTrail logging to a versioned S3 bucket creates two compounding cost 
drivers: continuous log growth from high-frequency event capture, and 
version retention that preserves every prior copy of every object 
indefinitely by default. Left unmanaged, storage cost grows in a way that 
isn't visible from the current-state view of the bucket, since the 
console shows the latest version, not the accumulated history behind it.

## Why This Was Missed Initially
Billing alarms were in place, but they alert on spend thresholds after 
the cost is incurred, not on the underlying resource accumulation that 
causes it. Versioned objects don't appear in a typical resource inventory 
check unless version listing is explicitly queried, so the exposure was 
invisible to standard verification steps.

## Mitigation
- Lifecycle policies to transition or expire noncurrent versions on a 
  defined schedule, rather than retaining them indefinitely
- Cost monitoring at the resource level (storage class, version count), 
  not just account-level billing alerts
- Teardown procedures that explicitly enumerate and remove versions, 
  since standard deletion and `terraform destroy` do not

## Architectural Principle
Cost governance has to be a design-time input, not a monitoring-time 
control. Alarms tell you something is happening; they don't tell you 
whether the resource model itself was correctly scoped from the start.
