# Script para otorgar permisos a los 2 secrets
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  OTORGANDO PERMISOS A LOS 2 SECRETS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Obtener cuenta de servicio
Write-Host "1. Obteniendo cuenta de servicio..." -ForegroundColor Yellow
$serviceAccount = & $gcloudPath run services describe violetas-app --region europe-west9 --project residencias-479706 --format="value(spec.template.spec.serviceAccountName)" 2>$null

if (-not $serviceAccount -or $serviceAccount -eq "") {
    # Usar cuenta por defecto
    Write-Host "   No hay cuenta específica, usando cuenta por defecto..." -ForegroundColor Gray
    $projectNumber = & $gcloudPath projects describe residencias-479706 --format="value(projectNumber)"
    $serviceAccount = "$projectNumber-compute@developer.gserviceaccount.com"
}

Write-Host "   Cuenta de servicio: $serviceAccount" -ForegroundColor Green
Write-Host ""

# Otorgar permiso al SECRET 1: jwt-secret-key
Write-Host "2. Otorgando permiso a jwt-secret-key..." -ForegroundColor Yellow
& $gcloudPath secrets add-iam-policy-binding jwt-secret-key `
    --member "serviceAccount:$serviceAccount" `
    --role "roles/secretmanager.secretAccessor" `
    --project=residencias-479706

if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ Permiso otorgado a jwt-secret-key" -ForegroundColor Green
} else {
    Write-Host "   ❌ Error al otorgar permiso" -ForegroundColor Red
}

Write-Host ""

# Otorgar permiso al SECRET 2: db-password
Write-Host "3. Otorgando permiso a db-password..." -ForegroundColor Yellow
& $gcloudPath secrets add-iam-policy-binding db-password `
    --member "serviceAccount:$serviceAccount" `
    --role "roles/secretmanager.secretAccessor" `
    --project=residencias-479706

if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ Permiso otorgado a db-password" -ForegroundColor Green
} else {
    Write-Host "   ❌ Error al otorgar permiso" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FIN" -ForegroundColor Cyan
Write-Host ""

