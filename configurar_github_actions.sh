#!/bin/bash
# Script para configurar GitHub Actions

PROJECT_ID="residencias-479706"
SA_NAME="github-actions-deploy"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "=========================================="
echo "  CONFIGURACIÓN DE GITHUB ACTIONS"
echo "=========================================="
echo ""

# Paso 1: Crear Service Account
echo "1. Creando Service Account..."
gcloud iam service-accounts create "$SA_NAME" \
  --display-name="GitHub Actions Deploy" \
  --project="$PROJECT_ID" 2>/dev/null || echo "   ℹ️  Service Account ya existe"

echo "   Service Account: $SA_EMAIL"
echo ""

# Paso 2: Otorgar permisos
echo "2. Otorgando permisos necesarios..."

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/run.admin" 2>/dev/null

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/storage.admin" 2>/dev/null

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/artifactregistry.writer" 2>/dev/null

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/iam.serviceAccountUser" 2>/dev/null

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/cloudsql.client" 2>/dev/null

echo "   ✅ Permisos otorgados"
echo ""

# Paso 3: Crear clave JSON
echo "3. Creando clave JSON..."
KEY_FILE="github-actions-key.json"
gcloud iam service-accounts keys create "$KEY_FILE" \
  --iam-account="$SA_EMAIL" \
  --project="$PROJECT_ID"

if [ $? -eq 0 ]; then
    echo "   ✅ Clave creada en: $KEY_FILE"
    echo ""
    echo "=========================================="
    echo "  SIGUIENTE PASO: AÑADIR SECRET A GITHUB"
    echo "=========================================="
    echo ""
    echo "1. Ve a: https://github.com/Toninobandolero/Residencias/settings/secrets/actions"
    echo ""
    echo "2. Haz clic en 'New repository secret'"
    echo ""
    echo "3. Añade:"
    echo "   Name: GCP_SA_KEY"
    echo "   Secret: [Pega el contenido completo del archivo $KEY_FILE]"
    echo ""
    echo "4. Para ver el contenido, ejecuta:"
    echo "   cat $KEY_FILE"
    echo ""
    echo "⚠️  IMPORTANTE: El archivo $KEY_FILE contiene credenciales."
    echo "   No lo subas a GitHub. Ya está en .gitignore."
    echo ""
else
    echo "   ❌ Error al crear clave"
    exit 1
fi
