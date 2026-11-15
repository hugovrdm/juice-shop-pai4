#!/usr/bin/env bash
# Sube los informes a DefectDojo por API. Credenciales SOLO por variables de entorno (secrets).
set -euo pipefail
DIR="${1:-reports}"
: "${DD_URL:?}" "${DD_TOKEN:?}"
PRODUCT="${DD_PRODUCT:-juice-shop-pai4}"
ENGAGEMENT="CI-${BRANCH:-local}"

upload() {  # fichero  tipo_escaner
  [ -f "$DIR/$1" ] || { echo "No existe $1, se omite"; return 0; }
  echo "Subiendo $1 como '$2'"
  curl -sS --fail -X POST "$DD_URL/api/v2/import-scan/" \
    -H "Authorization: Token $DD_TOKEN" \
    -F "scan_type=$2" -F "file=@$DIR/$1" \
    -F "product_name=$PRODUCT" -F "engagement_name=$ENGAGEMENT" \
    -F "auto_create_context=true" -F "deduplication_on_engagement=true" \
    -F "commit_hash=${COMMIT:-}" -F "branch_tag=${BRANCH:-}" \
    -F "test_title=$2" -F "close_old_findings=false" >/dev/null
}
upload semgrep.json    "Semgrep JSON Report"
upload trivy-sca.json  "Trivy Scan"
upload trivy-iac.json  "Trivy Scan"
upload zap.xml         "ZAP Scan"
