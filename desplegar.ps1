$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "DESPLIEGUE A CLOUD RUN" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Configurando proyecto..." -ForegroundColor Yellow
& $gcloudPath config set project residencias-479706

Write-Host "Habilitando APIs..." -ForegroundColor Yellow
& $gcloudPath services enable run.googleapis.com --quiet
& $gcloudPath services enable cloudbuild.googleapis.com --quiet
& $gcloudPath services enable secretmanager.googleapis.com --quiet
& $gcloudPath services enable artifactregistry.googleapis.com --quiet

Write-Host "Verificando repositorio Docker..." -ForegroundColor Yellow
$repoCheck = & $gcloudPath artifacts repositories describe violetas-app --location=europe-west9 2>&1
if ($LASTEXITCODE -ne 0) {
    & $gcloudPath artifacts repositories create violetas-app --repository-format=docker --location=europe-west9 --quiet
}

Write-Host "Verificando secretos..." -ForegroundColor Yellow
$jwtCheck = & $gcloudPath secrets describe jwt-secret-key 2>&1
if ($LASTEXITCODE -ne 0) {
    "temp_jwt_secret_$(Get-Random)" | & $gcloudPath secrets create jwt-secret-key --data-file=-
}

$dbCheck = & $gcloudPath secrets describe db-password 2>&1
if ($LASTEXITCODE -ne 0) {
    "V)R]y2&.#If-D0RM" | & $gcloudPath secrets create db-password --data-file=-
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "INICIANDO DESPLIEGUE..." -ForegroundColor Yellow
Write-Host "Esto puede tardar 5-10 minutos" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

& $gcloudPath run deploy violetas-app `
    --source . `
    --region europe-west9 `
    --platform managed `
    --allow-unauthenticated `
    --add-cloudsql-instances residencias-479706:europe-west9:residencias `
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias" `
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" `
    --memory 1Gi `
    --cpu 1 `
    --timeout 300 `
    --max-instances 10 `
    --min-instances 1

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "DESPLIEGUE COMPLETADO" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    $url = & $gcloudPath run services describe violetas-app --region europe-west9 --format="value(status.url)"
    Write-Host "URL de la aplicacion: $url" -ForegroundColor Cyan
}

