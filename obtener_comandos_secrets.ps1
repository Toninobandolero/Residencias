# Script que obtiene tu cuenta y muestra los comandos exactos
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  COMANDOS EXACTOS PARA TUS SECRETS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Obtener projectNumber
Write-Host "Obteniendo tu número de proyecto..." -ForegroundColor Yellow
$projectNumber = & $gcloudPath projects describe residencias-479706 --format="value(projectNumber)"

if ($projectNumber) {
    $serviceAccount = "$projectNumber-compute@developer.gserviceaccount.com"
    
    Write-Host "✅ Tu cuenta de servicio es:" -ForegroundColor Green
    Write-Host "   $serviceAccount" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "COMANDOS PARA EJECUTAR:" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "1. Para jwt-secret-key:" -ForegroundColor Yellow
    Write-Host "gcloud secrets add-iam-policy-binding jwt-secret-key --member `"serviceAccount:$serviceAccount`" --role `"roles/secretmanager.secretAccessor`" --project=residencias-479706" -ForegroundColor White
    Write-Host ""
    
    Write-Host "2. Para db-password:" -ForegroundColor Yellow
    Write-Host "gcloud secrets add-iam-policy-binding db-password --member `"serviceAccount:$serviceAccount`" --role `"roles/secretmanager.secretAccessor`" --project=residencias-479706" -ForegroundColor White
    Write-Host ""
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "¿Quieres que los ejecute automáticamente? (S/N): " -NoNewline -ForegroundColor Yellow
    $respuesta = Read-Host
    
    if ($respuesta -eq 'S' -or $respuesta -eq 's') {
        Write-Host ""
        Write-Host "Ejecutando comandos..." -ForegroundColor Yellow
        Write-Host ""
        
        Write-Host "Ejecutando comando 1..." -ForegroundColor Gray
        & $gcloudPath secrets add-iam-policy-binding jwt-secret-key --member "serviceAccount:$serviceAccount" --role "roles/secretmanager.secretAccessor" --project=residencias-479706
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ jwt-secret-key: Permiso otorgado" -ForegroundColor Green
        } else {
            Write-Host "❌ jwt-secret-key: Error" -ForegroundColor Red
        }
        
        Write-Host ""
        Write-Host "Ejecutando comando 2..." -ForegroundColor Gray
        & $gcloudPath secrets add-iam-policy-binding db-password --member "serviceAccount:$serviceAccount" --role "roles/secretmanager.secretAccessor" --project=residencias-479706
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ db-password: Permiso otorgado" -ForegroundColor Green
        } else {
            Write-Host "❌ db-password: Error" -ForegroundColor Red
        }
        
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "FIN" -ForegroundColor Cyan
    }
} else {
    Write-Host "❌ No se pudo obtener el número de proyecto" -ForegroundColor Red
    Write-Host "Verifica que estés autenticado: gcloud auth login" -ForegroundColor Yellow
}

Write-Host ""

