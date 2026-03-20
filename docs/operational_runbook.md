# Operational Runbook

## Issue: BucketNotEmpty

1. Stop CloudTrail
2. Delete versions + markers
3. Verify bucket empty
4. Re-run terraform destroy
