locals {
  name_prefix = "${var.project_name}-${var.environment}"
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
  })
}

# ─── LOGGING (deploy first — other modules depend on audit bucket) ───────────

module "logging" {
  source = "./modules/logging"

  name_prefix               = local.name_prefix
  aws_region                = var.aws_region
  cloudtrail_retention_days = var.cloudtrail_retention_days
  audit_s3_retention_days   = var.audit_s3_retention_days
}

# ─── IAM (shared policies used by Lambda modules) ─────────────────────────────

module "iam" {
  source = "./modules/iam"

  name_prefix      = local.name_prefix
  audit_bucket_arn = module.logging.audit_bucket_arn
}

# ─── SNS (alert topic — referenced by Lambda and Step Functions) ──────────────

module "sns" {
  source = "./modules/sns"

  name_prefix = local.name_prefix
  alert_email = var.alert_email
}

# ─── GUARDDUTY ────────────────────────────────────────────────────────────────

module "guardduty" {
  source = "./modules/guardduty"

  name_prefix               = local.name_prefix
  enable_guardduty          = var.enable_guardduty
  finding_publish_frequency = var.guardduty_finding_frequency

  findings_bucket_arn = module.logging.audit_bucket_arn
  kms_key_arn         = module.logging.kms_key_arn
}

# ─── SECURITY HUB ─────────────────────────────────────────────────────────────

module "security_hub" {
  source = "./modules/security-hub"

  aws_region          = var.aws_region
  name_prefix         = local.name_prefix
  enable_security_hub = var.enable_security_hub

  depends_on = [module.guardduty]
}

# ─── LAMBDA FUNCTIONS ─────────────────────────────────────────────────────────

module "lambda" {
  source = "./modules/lambda"

  name_prefix               = local.name_prefix
  aws_region                = var.aws_region
  sns_alert_topic_arn       = module.sns.alert_topic_arn
  audit_bucket_name         = module.logging.audit_bucket_name
  audit_bucket_arn          = module.logging.audit_bucket_arn
  lambda_log_retention_days = var.lambda_log_retention_days
  shared_policy_arns        = module.iam.shared_policy_arns
}

# ─── STEP FUNCTIONS STATE MACHINES ───────────────────────────────────────────

module "step_functions" {
  source = "./modules/step-functions"

  name_prefix = local.name_prefix
  aws_region  = var.aws_region

  enrich_finding_lambda_arn  = module.lambda.enrich_finding_arn
  notify_soc_lambda_arn      = module.lambda.notify_soc_arn
  iam_remediation_lambda_arn = module.lambda.iam_remediation_arn
  ec2_isolation_lambda_arn   = module.lambda.ec2_isolation_arn
  write_audit_lambda_arn     = module.lambda.write_audit_arn

  cloudwatch_log_group_arn = module.logging.sfn_log_group_arn
}

# ─── EVENTBRIDGE ROUTING ──────────────────────────────────────────────────────

module "eventbridge" {
  source = "./modules/eventbridge"

  name_prefix = local.name_prefix

  iam_state_machine_arn = module.step_functions.iam_state_machine_arn
  ec2_state_machine_arn = module.step_functions.ec2_state_machine_arn
  sfn_invoke_role_arn   = module.step_functions.eventbridge_invoke_role_arn
}
