# Lessons Learned

- Versioned S3 buckets retain every prior version by default; deleting the 
  "current" object does not remove the underlying versions. Any teardown 
  process must account for this explicitly, not assume `terraform destroy` 
  will handle it.

- CloudTrail can generate a high volume of log objects quickly, especially 
  in multi-region or multi-account setups. Cost and storage growth need to 
  be modeled at design time, not discovered after deployment.

- Large numbers of retained object versions and delete markers can complicate Terraform teardown and prevent versioned bucket deletion. Resource lifecycle and teardown behavior need to be considered during design rather than treated as an infrastructure tooling problem after deployment.g.

- At scale, lifecycle policies and batched cleanup provide a more manageable approach to version retention and teardown than relying on ad hoc deletion during environment destruction..

## Architectural takeaway
Security controls like logging and versioning create long-term operational 
and cost liabilities that don't show up until teardown or scale. Every 
project since this one includes a documented teardown plan and lifecycle 
policy at design time, not as a remediation step after deployment.
