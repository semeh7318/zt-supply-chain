#!/bin/bash
set -euo pipefail

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Vérifier que cosign et jq sont installés
if ! command -v cosign &> /dev/null; then
    echo -e "${RED}ERREUR: cosign n'est pas installé${NC}" >&2
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${RED}ERREUR: jq n'est pas installé${NC}" >&2
    exit 1
fi

# Image par défaut
DEFAULT_IMAGE="ghcr.io/semeh7318/zt-app:latest"
IMAGE="${1:-$DEFAULT_IMAGE}"

# Créer le répertoire reports s'il n'existe pas
mkdir -p "$(dirname "$0")/../reports"

# Date du jour
DATE=$(date +%Y-%m-%d)
REPORT_FILE="$(dirname "$0")/../reports/audit-$DATE.md"

# Variables pour les résultats
SIGNATURE_RESULT="KO"
SBOM_RESULT="KO"
DIGEST=""
PACKAGE_COUNT=0

echo "Audit de l'image : $IMAGE"
echo "================================"

# 1. Vérifier la signature
echo -n "Vérification de la signature... "
if cosign verify \
    --certificate-identity-regexp "https://github.com/semeh7318/zt-supply-chain/.*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$IMAGE" &> /dev/null; then
    echo -e "${GREEN}OK${NC}"
    SIGNATURE_RESULT="OK"
    # Récupérer le digest
    DIGEST=$(cosign triangulate "$IMAGE" 2>/dev/null || echo "")
else
    echo -e "${RED}KO${NC}"
fi

# 2. Vérifier l'attestation SBOM
echo -n "Vérification de l'attestation SBOM... "
if cosign verify-attestation \
    --type spdxjson \
    --certificate-identity-regexp "https://github.com/semeh7318/zt-supply-chain/.*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$IMAGE" &> /dev/null; then
    echo -e "${GREEN}OK${NC}"
    SBOM_RESULT="OK"
    # Compter les paquets dans le SBOM
    SBOM_JSON=$(cosign verify-attestation \
        --type spdxjson \
        --certificate-identity-regexp "https://github.com/semeh7318/zt-supply-chain/.*" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "$IMAGE" 2>/dev/null)
    PACKAGE_COUNT=$(echo "$SBOM_JSON" | jq '[.payload | @base64d | fromjson | .predicate | .sbom // [] | .packages // []] | add | length' 2>/dev/null || echo "0")
else
    echo -e "${RED}KO${NC}"
fi

# 3. Générer le rapport
cat > "$REPORT_FILE" <<EOF
# Audit de l'image - $DATE

- **Date** : $DATE
- **Image** : $IMAGE
- **Digest** : ${DIGEST:-"N/A"}
- **Résultat signature** : $SIGNATURE_RESULT
- **Résultat SBOM** : $SBOM_RESULT
- **Nombre de paquets** : $PACKAGE_COUNT
EOF

echo "Rapport généré : $REPORT_FILE"

# 4. Code de sortie
if [ "$SIGNATURE_RESULT" = "KO" ] || [ "$SBOM_RESULT" = "KO" ]; then
    exit 1
fi

exit 0
