#!/usr/bin/env bash
# package_lambdas.sh
# Zips all Lambda functions into lambda/dist/ for Terraform to consume.
# Run from the repo root before terraform plan/apply.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"

echo "Creating dist directory..."
mkdir -p "$DIST_DIR"

FUNCTIONS=("enrich_finding" "notify_soc" "iam_remediation" "ec2_isolation" "write_audit")

for fn in "${FUNCTIONS[@]}"; do
    SRC="${SCRIPT_DIR}/${fn}"
    OUT="${DIST_DIR}/${fn}.zip"

    if [[ ! -d "$SRC" ]]; then
        echo "WARNING: Source directory not found: $SRC — skipping"
        continue
    fi

    echo "Packaging: ${fn} → ${OUT}"
    (cd "$SRC" && zip -r "$OUT" . -x "__pycache__/*" "*.pyc" "*.pyo" "test_*" "*_test.py")
    echo "  Size: $(du -sh "$OUT" | cut -f1)"
done

echo ""
echo "All Lambda functions packaged. Ready for terraform apply."
ls -lh "$DIST_DIR"
