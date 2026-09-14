# Compliance Mapping

This mapping illustrates how project controls can support selected
security and compliance objectives. It does not represent certification
or compliance attestation.

## NIST SP 800-53

| Control | Project Alignment |
|---|---|
| AU-2 | CloudTrail event logging supports event logging requirements |
| AU-6 | Logged events provide data for audit review and analysis |
| AU-9 | S3 protections and versioning support protection of audit information |
| AU-11 | S3 lifecycle and retention controls support audit-record retention |

## ISO/IEC 27001:2022

| Control | Project Alignment |
|---|---|
| A.8.15 Logging | CloudTrail provides logging of AWS API and account activity |
| A.8.16 Monitoring activities | CloudTrail data provides telemetry that can support security monitoring |
