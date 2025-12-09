# Script para ver logs detallados del último build
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LOGS DETALLADOS DEL ÚLTIMO BUILD" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Obtener el último build ID
Write-Host "Obteniendo ID del último build..." -ForegroundColor Yellow
$buildId = & $gcloudPath builds list --project=residencias-479706 --limit 1 --format="value(id)"

if ($buildId) {
    Write-Host "Build ID: $buildId" -ForegroundColor Green
    Write-Host ""
    Write-Host "Mostrando logs completos..." -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Mostrar logs completos
    & $gcloudPath builds log $buildId --project=residencias-479706
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Para ver solo errores, busca líneas con 'ERROR' o 'FAILED'" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "URL del build en consola web:" -ForegroundColor Cyan
    Write-Host "https://console.cloud.google.com/cloud-build/builds/$buildId?project=residencias-479706" -ForegroundColor Gray
} else {
    Write-Host "No se encontraron builds recientes" -ForegroundColor Red
}

