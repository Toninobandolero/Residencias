# Script para construir y desplegar manualmente la imagen
Write-Host "=== BUILD Y DEPLOY MANUAL ===" -ForegroundColor Cyan

# Variables
$PROJECT_ID = "residencias-479706"
$REGION = "europe-west9"
$SERVICE = "violetas-app"
$IMAGE = "europe-west9-docker.pkg.dev/$PROJECT_ID/cloud-run-source-deploy/$SERVICE"

# 1. Construir imagen localmente con Cloud Build
Write-Host "`n1. Construyendo imagen con Cloud Build..." -ForegroundColor Yellow
gcloud builds submit --tag $IMAGE --project=$PROJECT_ID --region=$REGION

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build falló" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Build exitoso" -ForegroundColor Green

# 2. Desplegar imagen a Cloud Run
Write-Host "`n2. Desplegando a Cloud Run..." -ForegroundColor Yellow
gcloud run deploy $SERVICE `
    --image $IMAGE `
    --region $REGION `
    --platform managed `
    --allow-unauthenticated `
    --add-cloudsql-instances "${PROJECT_ID}:${REGION}:residencias" `
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=${PROJECT_ID}:${REGION}:residencias,GCS_BUCKET_NAME=violetas-documentos" `
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" `
    --memory 2Gi `
    --cpu 2 `
    --timeout 300 `
    --max-instances 10 `
    --min-instances 0 `
    --project=$PROJECT_ID

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Deploy falló" -ForegroundColor Red
    exit 1
}

Write-Host "`n✅ Deploy exitoso" -ForegroundColor Green

# 3. Verificar estado
Write-Host "`n3. Verificando estado..." -ForegroundColor Yellow
$url = gcloud run services describe $SERVICE --region $REGION --project $PROJECT_ID --format="value(status.url)"
Write-Host "URL: $url" -ForegroundColor Cyan

# 4. Probar health check
Write-Host "`n4. Probando health check..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
try {
    $response = Invoke-WebRequest -Uri "$url/health" -TimeoutSec 10
    Write-Host "✅ Health check OK: $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Health check falló: $_" -ForegroundColor Yellow
    Write-Host "Ver logs: gcloud run services logs read $SERVICE --region $REGION --project $PROJECT_ID" -ForegroundColor Gray
}

