# Despliegue SIMPLE a Cloud Run usando buildpacks automáticos (sin Dockerfile)
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "Desplegando con buildpacks automáticos..." -ForegroundColor Cyan
Write-Host "(No necesita Dockerfile, Google detecta automáticamente que es Python/Flask)" -ForegroundColor Gray
Write-Host ""

& $gcloudPath run deploy violetas-app `
    --source . `
    --region europe-west9 `
    --platform managed `
    --allow-unauthenticated `
    --add-cloudsql-instances residencias-479706:europe-west9:residencias `
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias,GCS_BUCKET_NAME=violetas-documentos" `
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" `
    --memory 2Gi `
    --cpu 2 `
    --timeout 300 `
    --max-instances 10 `
    --min-instances 0 `
    --project=residencias-479706

if ($LASTEXITCODE -eq 0) {
    $url = & $gcloudPath run services describe violetas-app --region europe-west9 --format="value(status.url)" --project=residencias-479706
    Write-Host ""
    Write-Host "URL: $url" -ForegroundColor Green
} else {
    Write-Host "Error. Revisa: https://console.cloud.google.com/run?project=residencias-479706" -ForegroundColor Red
}


