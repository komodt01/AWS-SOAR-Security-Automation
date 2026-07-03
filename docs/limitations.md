# Limitations

## S3 Versioning and Resource Lifecycle

### Limitation
Terraform cannot fully destroy S3 buckets containing versioned objects.

### Impact
Infrastructure teardown is not completely automated. Versioned objects must be removed before bucket deletion can succeed.

### Mitigation
- Documented manual cleanup procedure
- Verification checklist included in destroy.md
- Resource inventory validated before project completion

### Architectural Consideration
Infrastructure as Code simplifies deployment, but lifecycle management must account for cloud service behaviors that cannot be automated solely through Terraform.
