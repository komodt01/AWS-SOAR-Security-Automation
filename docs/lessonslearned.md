# Lessons Learned

* Versioned S3 buckets retain prior object versions. Deleting the current object does not remove the underlying versions. Teardown planning must account for this explicitly rather than assuming `terraform destroy` will handle every retained object.

* CloudTrail can generate a high volume of log objects quickly. Storage growth, retention, and cost need to be considered during architecture design rather than discovered after deployment.

* Large numbers of retained object versions and delete markers can complicate Terraform teardown and prevent versioned bucket deletion. Resource lifecycle and teardown behavior should be treated as architecture concerns rather than infrastructure-tooling problems discovered at the end of a deployment.

* At scale, lifecycle policies and controlled batched cleanup provide a more manageable approach to version retention than relying on ad hoc deletion during environment destruction.

## Architectural Takeaway

Security controls such as logging, versioning, and evidence retention create operational and cost consequences that may not become visible until the environment reaches scale or needs to be decommissioned.

The lesson carried forward from this project is to consider **security-control lifecycle, retention, cost, and teardown behavior during design**, rather than treating them as cleanup concerns after implementation.
