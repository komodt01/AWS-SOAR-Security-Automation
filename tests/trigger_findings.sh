#!/usr/bin/env bash
# =============================================================================
# trigger_findings.sh
#
# Generate GuardDuty sample findings and validate the AWS SOAR pipeline.
#
# Usage:
#   ./trigger_findings.sh iam
#   ./trigger_findings.sh ec2
#   ./trigger_findings.sh all
#   ./trigger_findings.sh watch
#   ./trigger_findings.sh validate
#   ./trigger_findings.sh artifacts
#
# Prerequisites:
#   - AWS CLI configured with appropriate permissions
#   - Terraform deployment completed for commands that interact with AWS
#   - jq installed
# =============================================================================

set -euo pipefail


# ─── OUTPUT FORMATTING ────────────────────────────────────────────────────────

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info() {
    echo -e "${CYAN}[INFO]${RESET}  $*"
}

success() {
    echo -e "${GREEN}[OK]${RESET}    $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${RESET}  $*"
}

error() {
    echo -e "${RED}[ERROR]${RESET} $*" >&2
}

header() {
    echo -e "\n${BOLD}${CYAN}=== $* ===${RESET}\n"
}


# ─── CONFIGURATION ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"

REGION="${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}"
REGION="${REGION:-us-east-1}"

NAME_PREFIX="${SOAR_NAME_PREFIX:-soar}"


# ─── DEPENDENCY CHECK ─────────────────────────────────────────────────────────

check_deps() {
    for cmd in aws jq terraform; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done

    success "Required tools available"
}


# ─── LOAD TERRAFORM OUTPUTS ───────────────────────────────────────────────────

load_tf_outputs() {
    info "Loading Terraform outputs..."

    pushd "$TERRAFORM_DIR" >/dev/null

    DETECTOR_ID="$(terraform output -raw guardduty_detector_id 2>/dev/null || true)"
    IAM_SFN_ARN="$(terraform output -raw iam_state_machine_arn 2>/dev/null || true)"
    EC2_SFN_ARN="$(terraform output -raw ec2_state_machine_arn 2>/dev/null || true)"
    AUDIT_BUCKET="$(terraform output -raw audit_bucket_name 2>/dev/null || true)"

    popd >/dev/null

    if [[ -z "$DETECTOR_ID" ]]; then
        error "GuardDuty detector ID not found."
        error "Deploy the environment with Terraform before running this command."
        exit 1
    fi

    success "Detector ID  : $DETECTOR_ID"

    if [[ -n "$IAM_SFN_ARN" ]]; then
        success "IAM SFN ARN  : $IAM_SFN_ARN"
    fi

    if [[ -n "$EC2_SFN_ARN" ]]; then
        success "EC2 SFN ARN  : $EC2_SFN_ARN"
    fi

    if [[ -n "$AUDIT_BUCKET" ]]; then
        success "Audit Bucket : $AUDIT_BUCKET"
    fi
}


# ─── IAM FINDING ──────────────────────────────────────────────────────────────

trigger_iam() {
    header "Triggering IAM Credential Finding"

    aws guardduty create-sample-findings \
        --detector-id "$DETECTOR_ID" \
        --finding-types "UnauthorizedAccess:IAMUser/AnomalousBehavior" \
        --region "$REGION"

    success "IAM sample finding generated"
    info "Allow time for GuardDuty → Security Hub → EventBridge processing."
}


# ─── EC2 FINDING ──────────────────────────────────────────────────────────────

trigger_ec2() {
    header "Triggering EC2 Backdoor / C2 Finding"

    aws guardduty create-sample-findings \
        --detector-id "$DETECTOR_ID" \
        --finding-types "Backdoor:EC2/C&CActivity.B" \
        --region "$REGION"

    success "EC2 sample finding generated"
    info "Allow time for GuardDuty → Security Hub → EventBridge processing."
}


# ─── WATCH STEP FUNCTIONS ─────────────────────────────────────────────────────

watch_executions() {
    header "Watching Step Functions Executions"

    info "Polling every 10 seconds. Press Ctrl+C to stop."
    echo ""

    while true; do
        echo -e "${BOLD}--- $(date '+%H:%M:%S') ---${RESET}"

        if [[ -n "$IAM_SFN_ARN" ]]; then
            echo -e "${CYAN}IAM Playbook:${RESET}"

            aws stepfunctions list-executions \
                --state-machine-arn "$IAM_SFN_ARN" \
                --max-results 3 \
                --region "$REGION" \
                --query \
                'executions[].{Name:name,Status:status,Start:startDate}' \
                --output table \
                2>/dev/null || warn "Unable to query IAM executions"
        fi

        if [[ -n "$EC2_SFN_ARN" ]]; then
            echo -e "${CYAN}EC2 Playbook:${RESET}"

            aws stepfunctions list-executions \
                --state-machine-arn "$EC2_SFN_ARN" \
                --max-results 3 \
                --region "$REGION" \
                --query \
                'executions[].{Name:name,Status:status,Start:startDate}' \
                --output table \
                2>/dev/null || warn "Unable to query EC2 executions"
        fi

        sleep 10
    done
}


# ─── PIPELINE VALIDATION ──────────────────────────────────────────────────────

validate_pipeline() {
    header "Validating SOAR Pipeline"

    GD_STATUS="$(
        aws guardduty get-detector \
            --detector-id "$DETECTOR_ID" \
            --region "$REGION" \
            --query 'Status' \
            --output text \
            2>/dev/null || echo "ERROR"
    )"

    if [[ "$GD_STATUS" == "ENABLED" ]]; then
        success "GuardDuty: ENABLED"
    else
        warn "GuardDuty: $GD_STATUS"
    fi


    SH_STATUS="$(
        aws securityhub describe-hub \
            --region "$REGION" \
            --query 'HubArn' \
            --output text \
            2>/dev/null || echo "NOT_ENABLED"
    )"

    if [[ "$SH_STATUS" != "NOT_ENABLED" ]]; then
        success "Security Hub: ENABLED"
    else
        warn "Security Hub: NOT_ENABLED"
    fi


    echo ""
    info "EventBridge Rules"

    aws events list-rules \
        --name-prefix "$NAME_PREFIX" \
        --region "$REGION" \
        --query 'Rules[].{Name:Name,State:State}' \
        --output table \
        2>/dev/null || \
        warn "Unable to find EventBridge rules using prefix '$NAME_PREFIX'"


    echo ""
    info "Lambda Functions"

    aws lambda list-functions \
        --region "$REGION" \
        --query \
        "Functions[?starts_with(FunctionName, '${NAME_PREFIX}')].{Name:FunctionName,Runtime:Runtime,State:State}" \
        --output table \
        2>/dev/null || \
        warn "Unable to find Lambda functions using prefix '$NAME_PREFIX'"


    echo ""
    info "Step Functions State Machines"

    aws stepfunctions list-state-machines \
        --region "$REGION" \
        --query \
        "stateMachines[?starts_with(name, '${NAME_PREFIX}')].{Name:name,ARN:stateMachineArn}" \
        --output table \
        2>/dev/null || \
        warn "Unable to find state machines using prefix '$NAME_PREFIX'"

    echo ""
    success "Pipeline validation complete"
}


# ─── AUDIT ARTIFACTS ──────────────────────────────────────────────────────────

check_artifacts() {
    header "Checking Audit Artifacts"

    if [[ -z "$AUDIT_BUCKET" ]]; then
        warn "Audit bucket name not found in Terraform outputs"
        return
    fi

    info "Recent artifacts in:"
    info "s3://${AUDIT_BUCKET}/playbook-artifacts/"

    aws s3 ls \
        "s3://${AUDIT_BUCKET}/playbook-artifacts/" \
        --recursive \
        --region "$REGION" |
        sort -r |
        head -20 ||
        info "No artifacts found"
}


# ─── HELP ─────────────────────────────────────────────────────────────────────

show_help() {
    echo ""
    echo -e "${BOLD}Usage:${RESET} $0 <command>"
    echo ""
    echo "Commands:"
    echo "  iam        Trigger IAM credential-compromise sample finding"
    echo "  ec2        Trigger EC2 backdoor/C2 sample finding"
    echo "  all        Trigger both sample findings"
    echo "  watch      Poll Step Functions executions every 10 seconds"
    echo "  validate   Validate deployed SOAR pipeline components"
    echo "  artifacts  List recent SOAR audit artifacts"
    echo "  help       Display this help"
    echo ""
    echo "Optional environment variables:"
    echo "  AWS_DEFAULT_REGION   AWS region used by the test script"
    echo "  SOAR_NAME_PREFIX     Terraform name_prefix value (default: soar)"
    echo ""
}


# ─── MAIN ─────────────────────────────────────────────────────────────────────

main() {
    local cmd="${1:-help}"

    case "$cmd" in
        help|-h|--help)
            show_help
            exit 0
            ;;
    esac

    check_deps
    load_tf_outputs

    case "$cmd" in
        iam)
            trigger_iam
            info "Then run: ./trigger_findings.sh watch"
            ;;

        ec2)
            trigger_ec2
            info "Then run: ./trigger_findings.sh watch"
            ;;

        all)
            trigger_iam
            sleep 2
            trigger_ec2
            info "Then run: ./trigger_findings.sh watch"
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

        *)
            error "Unknown command: $cmd"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
