# Lessons Learned

- Versioned S3 buckets retain every prior version by default; deleting the 
  "current" object does not remove the underlying versions. Any teardown 
  process must account for this explicitly, not assume `terraform destroy` 
  will handle it.

- CloudTrail can generate a high volume of log objects quickly, especially 
  in multi-region or multi-account setups. Cost and storage growth need to 
  be modeled at design time, not discovered after deployment.

- Terraform's native destroy does not reliably clean up versioned buckets 
  at scale, since it has to enumerate and delete every version individually. 
  This is a known limitation, not a misconfiguration, and needs to be 
  designed around rather than treated as a Terraform bug.

- Batch/lifecycle-based deletion (rather than relying on destroy alone) is 
  required for versioned buckets at any meaningful scale.

## Architectural takeaway
Security controls like logging and versioning create long-term operational 
and cost liabilities that don't show up until teardown or scale. Every 
project since this one includes a documented teardown plan and lifecycle 
policy at design time, not as a remediation step after deployment.
