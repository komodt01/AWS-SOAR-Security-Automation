output "iam_state_machine_arn" { value = aws_sfn_state_machine.iam_playbook.arn }
output "ec2_state_machine_arn" { value = aws_sfn_state_machine.ec2_playbook.arn }
output "eventbridge_invoke_role_arn" { value = aws_iam_role.eventbridge_invoke_sfn.arn }
