#!/usr/bin/env bash
# =============================================================================
# setup_github.sh
# Initializes the local git repo, sets up branch protection, and pushes
# aws-soar-security-automation to GitHub.
#
# Prerequisites:
#   - GitHub CLI (gh) installed: https://cli.github.com
#     macOS:  brew install gh
#     Linux:  sudo apt install gh  OR  see https://github.com/cli/cli
#   - Logged in: gh auth login
#   - AWS CLI configured (for OIDC trust policy creation)
#   - jq installed
#
# Usage:
#   chmod +x setup_github.sh
#   ./setup_github.sh
# =============================================================================

set -euo pipefail

# ─── COLORS ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  $*${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════${RESET}\n"; }
step()    { echo -e "\n${BOLD}▶ $*${RESET}"; }

# ─── CONFIG — edit these before running ──────────────────────────────────────
GITHUB_USERNAME="komodt01"
REPO_NAME="aws-soar-security-automation"
REPO_DESCRIPTION="AWS SOAR pipeline: GuardDuty → Security Hub → EventBridge → Step Functions | Terraform | SOC2 · FedRAMP · ISO27001"
REPO_VISIBILITY="public"          # public = visible in portfolio | private = hidden
DEFAULT_BRANCH="main"
AWS_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# OIDC role name (will be created in your AWS account for GitHub Actions)
OIDC_ROLE_NAME="github-actions-soar-deploy"

# ─── DERIVED ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"   # parent of setup_github.sh location
REPO_FULL="${GITHUB_USERNAME}/${REPO_NAME}"

# =============================================================================
# STEP 0 — Preflight checks
# =============================================================================
preflight() {
    header "Preflight Checks"

    local missing=()
    for cmd in git gh aws jq; do
        if command -v "$cmd" &>/dev/null; then
            success "$cmd found: $(command -v "$cmd")"
        else
            missing+=("$cmd")
            error "$cmd not found"
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        error "Missing dependencies: ${missing[*]}"
        echo ""
        echo "Install instructions:"
        echo "  gh  : brew install gh  OR  https://cli.github.com"
        echo "  jq  : brew install jq  OR  sudo apt install jq"
        echo "  aws : https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        exit 1
    fi

    # Check gh auth
    if ! gh auth status &>/dev/null; then
        error "GitHub CLI not authenticated. Run: gh auth login"
        exit 1
    fi
    success "GitHub CLI authenticated"

    # Check AWS identity
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")
    if [[ -z "$AWS_ACCOUNT_ID" ]]; then
        error "AWS CLI not configured. Run: aws configure"
        exit 1
    fi
    success "AWS account: $AWS_ACCOUNT_ID (region: $AWS_REGION)"

    echo ""
    info "Repo directory : $REPO_DIR"
    info "GitHub target  : https://github.com/${REPO_FULL}"
    info "AWS account    : $AWS_ACCOUNT_ID"
    echo ""
    read -rp "$(echo -e "${BOLD}Proceed? [y/N]: ${RESET}")" confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
}

# =============================================================================
# STEP 1 — Git init and initial commit
# =============================================================================
git_init() {
    header "Git Initialization"

    cd "$REPO_DIR"

    if [[ -d ".git" ]]; then
        warn ".git already exists — skipping git init"
    else
        step "Initializing git repository"
        git init -b "$DEFAULT_BRANCH"
        success "Git initialized with branch: $DEFAULT_BRANCH"
    fi

    # Configure git identity if not set
    if [[ -z "$(git config user.name 2>/dev/null || true)" ]]; then
        step "Configuring git identity"
        read -rp "  Your name: " git_name
        read -rp "  Your email: " git_email
        git config user.name "$git_name"
        git config user.email "$git_email"
    fi

    step "Staging all files"
    git add .

    # Show what we're about to commit
    echo ""
    info "Files to be committed:"
    git status --short | head -40
    echo ""

    step "Creating initial commit"
    git commit -m "feat: initial SOAR pipeline implementation

- GuardDuty → Security Hub → EventBridge → Step Functions pipeline
- IAM credential compromise playbook (disable keys + DenyAll policy)
- EC2 isolation playbook (EBS snapshot + quarantine security group)
- All Terraform modules: guardduty, security-hub, eventbridge,
  step-functions, lambda, sns, logging, iam
- Python Lambda handlers with least-privilege IAM execution roles
- GitHub Actions CI/CD: flake8 + bandit + terraform plan/apply
- Compliance mapping: SOC 2, FedRAMP Moderate, ISO 27001
- Test harness: GuardDuty sample finding generator + pipeline validator

Ref: https://github.com/${REPO_FULL}"

    success "Initial commit created"
}

# =============================================================================
# STEP 2 — Create GitHub repository
# =============================================================================
create_github_repo() {
    header "Creating GitHub Repository"

    # Check if repo already exists
    if gh repo view "$REPO_FULL" &>/dev/null; then
        warn "Repository ${REPO_FULL} already exists — skipping creation"
        return
    fi

    step "Creating repository: ${REPO_FULL}"
    gh repo create "$REPO_FULL" \
        --"$REPO_VISIBILITY" \
        --description "$REPO_DESCRIPTION" \
        --homepage "https://github.com/${REPO_FULL}" \
        --push \
        --source "$REPO_DIR" \
        --remote origin

    success "Repository created: https://github.com/${REPO_FULL}"
}

# =============================================================================
# STEP 3 — Configure repository settings
# =============================================================================
configure_repo() {
    header "Configuring Repository"

    step "Setting repository topics"
    gh repo edit "$REPO_FULL" \
        --add-topic "aws" \
        --add-topic "security" \
        --add-topic "soar" \
        --add-topic "terraform" \
        --add-topic "guardduty" \
        --add-topic "step-functions" \
        --add-topic "lambda" \
        --add-topic "devsecops" \
        --add-topic "fedramp" \
        --add-topic "soc2" \
        2>/dev/null || warn "Topic setting may have partially failed — check GitHub"
    success "Topics set"

    step "Enabling branch protection on main"
    gh api \
        --method PUT \
        -H "Accept: application/vnd.github+json" \
        "/repos/${REPO_FULL}/branches/${DEFAULT_BRANCH}/protection" \
        --field required_status_checks='{"strict":true,"contexts":["Validate Lambda Functions","Terraform Plan"]}' \
        --field enforce_admins=false \
        --field required_pull_request_reviews='{"required_approving_review_count":1}' \
        --field restrictions=null \
        2>/dev/null || warn "Branch protection requires GitHub Pro/Team for private repos — skipping if not available"
    success "Branch protection configured"
}

# =============================================================================
# STEP 4 — Create AWS OIDC provider + IAM role for GitHub Actions
# =============================================================================
setup_aws_oidc() {
    header "AWS OIDC Setup for GitHub Actions"

    info "This creates a trust relationship so GitHub Actions can authenticate"
    info "to AWS without long-lived access keys."
    echo ""

    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    OIDC_PROVIDER_URL="https://token.actions.githubusercontent.com"
    OIDC_PROVIDER_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"

    # ── Create OIDC provider if not exists ────────────────────────────────────
    step "Checking OIDC provider"
    if aws iam get-open-id-connect-provider \
            --open-id-connect-provider-arn "$OIDC_PROVIDER_ARN" \
            &>/dev/null; then
        success "OIDC provider already exists"
    else
        step "Creating GitHub OIDC provider"
        # Thumbprint for token.actions.githubusercontent.com
        THUMBPRINT="6938fd4d98bab03faadb97b34396831e3780aea1"
        aws iam create-open-id-connect-provider \
            --url "$OIDC_PROVIDER_URL" \
            --client-id-list "sts.amazonaws.com" \
            --thumbprint-list "$THUMBPRINT"
        success "OIDC provider created"
    fi

    # ── Create IAM role for GitHub Actions ────────────────────────────────────
    step "Creating IAM role: $OIDC_ROLE_NAME"

    TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GitHubActionsOIDC",
      "Effect": "Allow",
      "Principal": {
        "Federated": "${OIDC_PROVIDER_ARN}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:${REPO_FULL}:*"
        }
      }
    }
  ]
}
EOF
)

    # Check if role already exists
    if aws iam get-role --role-name "$OIDC_ROLE_NAME" &>/dev/null; then
        warn "IAM role $OIDC_ROLE_NAME already exists — updating trust policy"
        aws iam update-assume-role-policy \
            --role-name "$OIDC_ROLE_NAME" \
            --policy-document "$TRUST_POLICY"
    else
        aws iam create-role \
            --role-name "$OIDC_ROLE_NAME" \
            --assume-role-policy-document "$TRUST_POLICY" \
            --description "GitHub Actions OIDC role for aws-soar-security-automation deployments" \
            --tags Key=Project,Value=aws-soar-security-automation \
                   Key=ManagedBy,Value=setup_github.sh
        success "IAM role created: $OIDC_ROLE_NAME"
    fi

    # ── Attach deployment permissions ─────────────────────────────────────────
    step "Attaching deployment permissions to role"

    DEPLOY_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TerraformStateReadWrite",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
        "s3:ListBucket", "s3:GetBucketVersioning"
      ],
      "Resource": [
        "arn:aws:s3:::*terraform-state*",
        "arn:aws:s3:::*terraform-state*/*"
      ]
    },
    {
      "Sid": "TerraformStateLock",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem", "dynamodb:PutItem",
        "dynamodb:DeleteItem", "dynamodb:DescribeTable"
      ],
      "Resource": "arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/*terraform*"
    },
    {
      "Sid": "SOARResourceManagement",
      "Effect": "Allow",
      "Action": [
        "guardduty:*",
        "securityhub:*",
        "events:*",
        "states:*",
        "lambda:*",
        "sns:*",
        "s3:*",
        "cloudtrail:*",
        "logs:*",
        "iam:Get*", "iam:List*", "iam:Create*", "iam:Delete*",
        "iam:Put*", "iam:Attach*", "iam:Detach*", "iam:Tag*",
        "iam:Update*", "iam:PassRole",
        "xray:*"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)

    # Create inline policy on the role
    aws iam put-role-policy \
        --role-name "$OIDC_ROLE_NAME" \
        --policy-name "soar-deploy-permissions" \
        --policy-document "$DEPLOY_POLICY"
    success "Deployment permissions attached"

    ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${OIDC_ROLE_NAME}"

    # ── Set GitHub Actions secret ──────────────────────────────────────────────
    step "Setting GitHub Actions secret: AWS_OIDC_ROLE_ARN"
    gh secret set AWS_OIDC_ROLE_ARN \
        --repo "$REPO_FULL" \
        --body "$ROLE_ARN"
    success "Secret AWS_OIDC_ROLE_ARN set → $ROLE_ARN"
}

# =============================================================================
# STEP 5 — tfvars setup prompt
# =============================================================================
setup_tfvars() {
    header "Terraform Variables Setup"

    TFVARS_EXAMPLE="${REPO_DIR}/terraform/envs/dev/terraform.tfvars.example"
    TFVARS_FILE="${REPO_DIR}/terraform/envs/dev/terraform.tfvars"

    if [[ -f "$TFVARS_FILE" ]]; then
        warn "terraform.tfvars already exists — skipping"
        return
    fi

    step "Creating terraform.tfvars from example"
    cp "$TFVARS_EXAMPLE" "$TFVARS_FILE"

    # Prompt for required values
    echo ""
    read -rp "  SOC alert email address: " alert_email
    read -rp "  AWS region [$AWS_REGION]: " region_input
    region_input="${region_input:-$AWS_REGION}"

    # Substitute values in tfvars
    sed -i.bak \
        -e "s|your-soc-email@example.com|${alert_email}|g" \
        -e "s|us-east-1|${region_input}|g" \
        "$TFVARS_FILE"
    rm -f "${TFVARS_FILE}.bak"

    success "terraform.tfvars created with your values"
    warn "terraform.tfvars is in .gitignore and will NOT be committed"
}

# =============================================================================
# STEP 6 — Final push if repo was pre-existing
# =============================================================================
push_if_needed() {
    cd "$REPO_DIR"

    if ! git remote get-url origin &>/dev/null; then
        step "Adding remote origin"
        git remote add origin "https://github.com/${REPO_FULL}.git"
    fi

    # Only push if HEAD is ahead of origin
    if git status | grep -q "nothing to commit"; then
        if ! git ls-remote --exit-code origin "$DEFAULT_BRANCH" &>/dev/null; then
            step "Pushing to GitHub"
            git push -u origin "$DEFAULT_BRANCH"
            success "Pushed to https://github.com/${REPO_FULL}"
        else
            info "Branch already exists on remote — no push needed"
        fi
    fi
}

# =============================================================================
# STEP 7 — Summary
# =============================================================================
print_summary() {
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "N/A")

    header "Setup Complete"

    echo -e "${BOLD}Repository${RESET}"
    echo -e "  GitHub : https://github.com/${REPO_FULL}"
    echo -e "  Actions: https://github.com/${REPO_FULL}/actions"
    echo ""
    echo -e "${BOLD}AWS Resources Created${RESET}"
    echo -e "  OIDC Provider : token.actions.githubusercontent.com"
    echo -e "  IAM Role      : arn:aws:iam::${AWS_ACCOUNT_ID}:role/${OIDC_ROLE_NAME}"
    echo ""
    echo -e "${BOLD}Next Steps${RESET}"
    echo ""
    echo -e "  1. Deploy to AWS:"
    echo -e "     ${CYAN}cd terraform${RESET}"
    echo -e "     ${CYAN}terraform init${RESET}"
    echo -e "     ${CYAN}terraform plan -var-file=envs/dev/terraform.tfvars${RESET}"
    echo -e "     ${CYAN}terraform apply -var-file=envs/dev/terraform.tfvars${RESET}"
    echo ""
    echo -e "  2. Confirm the SNS subscription email that AWS sends you"
    echo ""
    echo -e "  3. Trigger a test finding:"
    echo -e "     ${CYAN}cd tests && chmod +x trigger_findings.sh${RESET}"
    echo -e "     ${CYAN}./trigger_findings.sh validate${RESET}   # verify pipeline is up"
    echo -e "     ${CYAN}./trigger_findings.sh iam${RESET}        # fire IAM playbook"
    echo -e "     ${CYAN}./trigger_findings.sh watch${RESET}      # watch executions"
    echo ""
    echo -e "  4. Watch the Step Functions execution graph:"
    echo -e "     ${CYAN}https://console.aws.amazon.com/states/home?region=${AWS_REGION}${RESET}"
    echo ""
    echo -e "  5. When done demoing, destroy resources to avoid GuardDuty charges:"
    echo -e "     ${CYAN}terraform destroy -var-file=envs/dev/terraform.tfvars${RESET}"
    echo ""
    echo -e "${BOLD}Portfolio link to share:${RESET}"
    echo -e "  https://github.com/${REPO_FULL}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    header "AWS SOAR — GitHub Repository Setup"
    info "Repo    : ${REPO_FULL}"
    info "Visible : ${REPO_VISIBILITY}"

    preflight
    git_init
    create_github_repo
    configure_repo
    setup_aws_oidc
    setup_tfvars
    push_if_needed
    print_summary
}

main "$@"
