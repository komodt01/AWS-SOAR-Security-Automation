output "enrich_finding_arn" { value = aws_lambda_function.enrich_finding.arn }
output "notify_soc_arn" { value = aws_lambda_function.notify_soc.arn }
output "iam_remediation_arn" { value = aws_lambda_function.iam_remediation.arn }
output "ec2_isolation_arn" { value = aws_lambda_function.ec2_isolation.arn }
output "write_audit_arn" { value = aws_lambda_function.write_audit.arn }
