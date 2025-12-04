$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "DESPLIEGUE A CLOUD RUN" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Esto puede tardar 5-10 minutos..." -ForegroundColor Gray
Write-Host ""

& $gcloudPath run deploy violetas-app `
    --source . `
    --region europe-west9 `
    --platform managed `
    --allow-unauthenticated `
    --add-cloudsql-instances residencias-479706:europe-west9:residencias `
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias" `
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" `
    --memory 2Gi `
    --cpu 2 `
    --timeout 300 `
    --max-instances 10 `
    --min-instances 0

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "DESPLIEGUE COMPLETADO" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    $url = & $gcloudPath run services describe violetas-app --region europe-west9 --format="value(status.url)" --project=residencias-479706
    
    Write-Host "URL DE TU APLICACION:" -ForegroundColor Cyan
    Write-Host $url -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Abre esta URL en tu navegador para acceder a la aplicacion" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "ERROR en el despliegue" -ForegroundColor Red
    Write-Host "Revisa los mensajes de error arriba" -ForegroundColor Yellow
}

