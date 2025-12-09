# Script para ver logs del último build específico
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LOGS DEL ÚLTIMO BUILD" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Obtener el último build
Write-Host "Obteniendo ID del último build..." -ForegroundColor Yellow
$builds = & $gcloudPath builds list --project=residencias-479706 --limit 1 --format="table(id,status,createTime)"

Write-Host $builds
Write-Host ""

$buildId = & $gcloudPath builds list --project=residencias-479706 --limit 1 --format="value(id)"

if ($buildId) {
    Write-Host "Build ID: $buildId" -ForegroundColor Green
    Write-Host ""
    Write-Host "Mostrando logs (busca ERROR, FAILED, ImportError)..." -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Mostrar logs y buscar errores
    $logs = & $gcloudPath builds log $buildId --project=residencias-479706 2>&1
    
    # Buscar líneas con ERROR o FAILED
    $errorLines = $logs | Select-String -Pattern "ERROR|FAILED|ImportError|ModuleNotFoundError|ValueError|Exception" -Context 2,2
    
    if ($errorLines) {
        Write-Host "════════════════════════════════════════" -ForegroundColor Red
        Write-Host "  ERRORES ENCONTRADOS:" -ForegroundColor Red
        Write-Host "════════════════════════════════════════" -ForegroundColor Red
        Write-Host ""
        $errorLines | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        Write-Host ""
    } else {
        Write-Host "No se encontraron errores obvios en los logs." -ForegroundColor Yellow
        Write-Host "Mostrando últimas 50 líneas..." -ForegroundColor Gray
        Write-Host ""
        $logs | Select-Object -Last 50
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "URL completa del build:" -ForegroundColor Cyan
    Write-Host "https://console.cloud.google.com/cloud-build/builds/$buildId?project=residencias-479706" -ForegroundColor Gray
} else {
    Write-Host "No se encontraron builds" -ForegroundColor Red
}

Write-Host ""

