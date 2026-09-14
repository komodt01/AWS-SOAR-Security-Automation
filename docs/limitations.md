# Limitations

## S3 Versioning and Resource Lifecycle

### Limitation
A versioned S3 bucket cannot be deleted while retained object versions and delete markers remain, which can prevent Terraform teardown from completing successfully.

### Impact
**Infrastructure teardown is not completely automated. Versioned objects must be removed before bucket deletion can succeed.
**
### Mitigation
- Documented manual cleanup procedure
- Verification checklist included in destroy.md
- Resource inventory validated before project completion

### Architectural Consideration
Infrastructure as Code simplifies deployment and teardown, but lifecycle design must account for cloud service behaviors and retained data that can affect resource deletion.
