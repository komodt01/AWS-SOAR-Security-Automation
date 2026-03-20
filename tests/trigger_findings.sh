#!/usr/bin/env bash
# =============================================================================
# trigger_findings.sh
# Generate GuardDuty sample findings to test the SOAR pipeline end-to-end.
#
# Usage:
#   ./trigger_findings.sh iam          # Trigger IAM credential finding
#   ./trigger_findings.sh ec2          # Trigger EC2 backdoor finding
#   ./trigger_findings.sh all          # Trigger both
#   ./trigger_findings.sh watch        # Tail Step Functions after triggering all
#
# Prerequisites:
#   - AWS CLI configured with appropriate permissions
#   - terraform apply completed (outputs must be available)
#   - jq installed (brew install jq / apt install jq)
# =============================================================================

set -euo pipefail

# ─── COLORS ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
header()  { echo -e "\n${BOLD}${CYAN}═══ $* ═══${RESET}\n"; }

# ─── CONFIG ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# ─── DEPENDENCY CHECK ─────────────────────────────────────────────────────────
check_deps() {
    for cmd in aws jq terraform; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done
    info "All dependencies present (aws, jq, terraform)"
}

# ─── LOAD TERRAFORM OUTPUTS ───────────────────────────────────────────────────
load_tf_outputs() {
    info "Loading Terraform outputs..."
    cd "$TERRAFORM_DIR"

    DETECTOR_ID=$(terraform output -raw guardduty_detector_id 2>/dev/null || echo "")
    IAM_SFN_ARN=$(terraform output -raw iam_state_machine_arn 2>/dev/null || echo "")
    EC2_SFN_ARN=$(terraform output -raw ec2_state_machine_arn 2>/dev/null || echo "")
    AUDIT_BUCKET=$(terraform output -raw audit_bucket_name 2>/dev/null || echo "")

    cd - >/dev/null

    if [[ -z "$DETECTOR_ID" ]]; then
        error "GuardDuty detector ID not found. Have you run 'terraform apply'?"
        exit 1
    fi

    success "Detector ID    : $DETECTOR_ID"
    success "IAM SFN ARN    : $IAM_SFN_ARN"
    success "EC2 SFN ARN    : $EC2_SFN_ARN"
    success "Audit Bucket   : $AUDIT_BUCKET"
}

# ─── TRIGGER IAM FINDING ─────────────────────────────────────────────────────
trigger_iam() {
    header "Triggering IAM Credential Compromise Finding"

    # GuardDuty sample finding type for unauthorized IAM access
    aws guardduty create-sample-findings \
        --detector-id "$DETECTOR_ID" \
        --finding-types "UnauthorizedAccess:IAMUser/AnomalousBehavior" \
        --region "$REGION"

    success "IAM sample finding generated"
    info "Finding will appear in GuardDuty → Security Hub → EventBridge within ~1 minute"
    info "Monitor: https://console.aws.amazon.com/guardduty/home?region=${REGION}#/findings"
}

# ─── TRIGGER EC2 FINDING ─────────────────────────────────────────────────────
trigger_ec2() {
    header "Triggering EC2 Backdoor / C2 Activity Finding"

    aws guardduty create-sample-findings \
        --detector-id "$DETECTOR_ID" \
        --finding-types "Backdoor:EC2/C&CActivity.B" \
        --region "$REGION"

    success "EC2 sample finding generated"
    info "Finding will appear in GuardDuty → Security Hub → EventBridge within ~1 minute"
    info "Monitor: https://console.aws.amazon.com/guardduty/home?region=${REGION}#/findings"
}

# ─── WATCH STEP FUNCTIONS ────────────────────────────────────────────────────
watch_executions() {
    header "Watching Step Functions Executions"
    info "Polling every 10 seconds... (Ctrl+C to stop)"
    echo ""

    while true; do
        echo -e "${BOLD}--- $(date '+%H:%M:%S') ---${RESET}"

        # IAM playbook executions
        if [[ -n "$IAM_SFN_ARN" ]]; then
            echo -e "${CYAN}IAM Playbook:${RESET}"
            aws stepfunctions list-executions \
                --state-machine-arn "$IAM_SFN_ARN" \
                --max-results 3 \
                --region "$REGION" \
                --query 'executions[].{Name:name,Status:status,Start:startDate}' \
                --output table 2>/dev/null || echo "  No executions yet"
        fi

        # EC2 playbook executions
        if [[ -n "$EC2_SFN_ARN" ]]; then
            echo -e "${CYAN}EC2 Playbook:${RESET}"
            aws stepfunctions list-executions \
                --state-machine-arn "$EC2_SFN_ARN" \
                --max-results 3 \
                --region "$REGION" \
                --query 'executions[].{Name:name,Status:status,Start:startDate}' \
                --output table 2>/dev/null || echo "  No executions yet"
        fi

        sleep 10
    done
}

# ─── VALIDATE PIPELINE ───────────────────────────────────────────────────────
validate_pipeline() {
    header "Validating SOAR Pipeline Components"

    # GuardDuty
    GD_STATUS=$(aws guardduty get-detector \
        --detector-id "$DETECTOR_ID" \
        --region "$REGION" \
        --query 'Status' --output text 2>/dev/null || echo "ERROR")
    [[ "$GD_STATUS" == "ENABLED" ]] && success "GuardDuty: ENABLED" || warn "GuardDuty: $GD_STATUS"

    # Security Hub
    SH_STATUS=$(aws securityhub describe-hub \
        --region "$REGION" \
        --query 'HubArn' --output text 2>/dev/null || echo "NOT_ENABLED")
    [[ "$SH_STATUS" != "NOT_ENABLED" ]] && success "Security Hub: ENABLED" || warn "Security Hub: NOT_ENABLED"

    # EventBridge rules
    echo ""
    info "EventBridge Rules:"
    aws events list-rules \
        --name-prefix "soar" \
        --region "$REGION" \
        --query 'Rules[].{Name:Name,State:State}' \
        --output table 2>/dev/null || warn "No EventBridge rules found with prefix 'soar'"

    # Lambda functions
    echo ""
    info "Lambda Functions:"
    aws lambda list-functions \
        --region "$REGION" \
        --query "Functions[?starts_with(FunctionName, 'soar')].{Name:FunctionName,Runtime:Runtime,State:State}" \
        --output table 2>/dev/null || warn "No Lambda functions found with prefix 'soar'"

    # State machines
    echo ""
    info "Step Functions State Machines:"
    aws stepfunctions list-state-machines \
        --region "$REGION" \
        --query "stateMachines[?starts_with(name, 'soar')].{Name:name,ARN:stateMachineArn}" \
        --output table 2>/dev/null || warn "No state machines found with prefix 'soar'"

    echo ""
    success "Pipeline validation complete"
}

# ─── AUDIT ARTIFACTS CHECK ───────────────────────────────────────────────────
check_artifacts() {
    header "Checking Audit Artifacts in S3"

    if [[ -z "$AUDIT_BUCKET" ]]; then
        warn "Audit bucket name not found in Terraform outputs"
        return
    fi

    info "Listing recent artifacts in s3://${AUDIT_BUCKET}/playbook-artifacts/"
    aws s3 ls "s3://${AUDIT_BUCKET}/playbook-artifacts/" --recursive \
        --region "$REGION" | sort -r | head -20 || info "No artifacts yet"
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────
main() {
    local cmd="${1:-help}"

    check_deps
    load_tf_outputs

    case "$cmd" in
        iam)
            trigger_iam
            info "Wait ~60 seconds then run: ./trigger_findings.sh watch"
            ;;
        ec2)
            trigger_ec2
            info "Wait ~60 seconds then run: ./trigger_findings.sh watch"
            ;;
        all)
            trigger_iam
            sleep 2
            trigger_ec2
            info "Wait ~60 seconds then run: ./trigger_findings.sh watch"
            ;;
        watch)
            watch_executions
            ;;
        validate)
            validate_pipeline
            ;;
        artifacts)
            check_artifacts
            ;;
        help|*)
            echo ""
            echo -e "${BOLD}Usage:${RESET} $0 <command>"
            echo ""
            echo "Commands:"
            echo "  iam        Trigger IAM credential compromise sample finding"
            echo "  ec2        Trigger EC2 backdoor/C2 sample finding"
            echo "  all        Trigger both IAM and EC2 findings"
            echo "  watch      Poll Step Functions executions every 10s"
            echo "  validate   Check all pipeline components are deployed and enabled"
            echo "  artifacts  List recent audit artifacts in S3"
            echo ""
            ;;
    esac
}

main "$@"
