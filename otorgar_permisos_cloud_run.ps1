# Script para otorgar permisos necesarios al servicio de Cloud Run
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  OTORGANDO PERMISOS A CLOUD RUN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Obtener cuenta de servicio del servicio
Write-Host "1. Obteniendo cuenta de servicio del servicio..." -ForegroundColor Yellow
$serviceAccount = & $gcloudPath run services describe violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --format="value(spec.template.spec.serviceAccountName)" 2>$null

if (-not $serviceAccount -or $serviceAccount -eq "") {
    # Si no tiene cuenta de servicio, usar la cuenta por defecto
    $projectNumber = & $gcloudPath projects describe residencias-479706 --format="value(projectNumber)"
    $serviceAccount = "$projectNumber-compute@developer.gserviceaccount.com"
    Write-Host "   Usando cuenta por defecto: $serviceAccount" -ForegroundColor Gray
} else {
    Write-Host "   Cuenta de servicio: $serviceAccount" -ForegroundColor Green
}

Write-Host ""

# Otorgar permisos a Secret Manager
Write-Host "2. Otorgando permisos a Secret Manager..." -ForegroundColor Yellow
Write-Host "   Permiso: roles/secretmanager.secretAccessor" -ForegroundColor Gray

& $gcloudPath secrets add-iam-policy-binding jwt-secret-key `
    --member "serviceAccount:$serviceAccount" `
    --role "roles/secretmanager.secretAccessor" `
    --project=residencias-479706 2>&1 | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ Permiso otorgado para jwt-secret-key" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Error al otorgar permiso para jwt-secret-key" -ForegroundColor Yellow
}

& $gcloudPath secrets add-iam-policy-binding db-password `
    --member "serviceAccount:$serviceAccount" `
    --role "roles/secretmanager.secretAccessor" `
    --project=residencias-479706 2>&1 | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ Permiso otorgado para db-password" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Error al otorgar permiso para db-password" -ForegroundColor Yellow
}

Write-Host ""

# Otorgar permisos a Cloud SQL
Write-Host "3. Otorgando permisos a Cloud SQL..." -ForegroundColor Yellow
Write-Host "   Permiso: roles/cloudsql.client" -ForegroundColor Gray

& $gcloudPath projects add-iam-policy-binding residencias-479706 `
    --member "serviceAccount:$serviceAccount" `
    --role "roles/cloudsql.client" `
    --condition=None 2>&1 | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ Permiso otorgado para Cloud SQL" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Error al otorgar permiso para Cloud SQL" -ForegroundColor Yellow
}

Write-Host ""

# Otorgar permisos a Cloud Storage
Write-Host "4. Otorgando permisos a Cloud Storage..." -ForegroundColor Yellow
Write-Host "   Permiso: roles/storage.objectAdmin" -ForegroundColor Gray

& $gcloudPath projects add-iam-policy-binding residencias-479706 `
    --member "serviceAccount:$serviceAccount" `
    --role "roles/storage.objectAdmin" `
    --condition=None 2>&1 | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ Permiso otorgado para Cloud Storage" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Error al otorgar permiso para Cloud Storage" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ✅ PERMISOS CONFIGURADOS" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Ahora redespliega el servicio:" -ForegroundColor Yellow
Write-Host "  .\deploy_mejorado.bat" -ForegroundColor Gray
Write-Host ""

