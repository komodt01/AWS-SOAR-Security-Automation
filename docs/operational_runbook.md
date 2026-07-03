# Operational Runbook

## Issue: BucketNotEmpty (Terraform destroy failure)

### Symptom
`terraform destroy` fails with a `BucketNotEmpty` error on a versioned 
S3 bucket used for CloudTrail logging, even though the bucket appears 
empty in the console. This happens because S3 versioning preserves 
every prior version and delete marker; the console's default view only 
shows current objects, masking the actual contents.

### Resolution Steps

1. **Stop CloudTrail logging to the bucket**
   Prevents new objects from being written while remediation is in 
   progress, avoiding a moving target.

2. **Delete all object versions and delete markers**
   Standard `aws s3 rm` or console deletion only removes current 
   versions. Every noncurrent version and delete marker must be removed 
   explicitly. At scale, this requires batched deletion (via script or 
   `aws s3api delete-objects` in batches) rather than one-by-one 
   deletion, which will time out on large version counts.

3. **Verify the bucket is fully empty**
   Confirm via `aws s3api list-object-versions` that both `Versions` 
   and `DeleteMarkers` return empty, not just the default object 
   listing.

4. **Re-run `terraform destroy`**
   Once version history is fully cleared, destroy should complete 
   normally.

### Prevention
- Apply an S3 lifecycle policy to expire noncurrent versions on a 
  defined schedule (e.g., 30/90 days) rather than retaining them 
  indefinitely
- Include version count / storage size as a pre-teardown verification 
  check, not just object presence
- Document teardown order for any environment using versioned buckets 
  before deployment, not after a failure
