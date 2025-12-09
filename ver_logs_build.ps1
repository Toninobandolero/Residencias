# Script para ver logs de construcción (build logs) de Cloud Run
# Uso: .\ver_logs_build.ps1

$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LOGS DE CONSTRUCCIÓN - CLOUD RUN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar que gcloud está disponible
if (-not (Test-Path $gcloudPath)) {
    Write-Host "ERROR: Google Cloud SDK no encontrado" -ForegroundColor Red
    Write-Host "Instala desde: https://cloud.google.com/sdk/docs/install" -ForegroundColor Yellow
    exit 1
}

Write-Host "1. Obteniendo información de la última revisión..." -ForegroundColor Yellow
Write-Host ""

# Obtener la última revisión
$revisiones = & $gcloudPath run revisions list `
    --service violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --format="value(name)" `
    --limit 1

if ($revisiones) {
    $ultimaRevision = $revisiones[0]
    Write-Host "   Última revisión: $ultimaRevision" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "2. Obteniendo detalles de la revisión..." -ForegroundColor Yellow
    Write-Host ""
    
    & $gcloudPath run revisions describe $ultimaRevision `
        --region europe-west9 `
        --project residencias-479706 `
        --format="yaml(status.conditions)"
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "3. Logs de construcción desde Cloud Build..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Nota: Los logs de construcción se almacenan en Cloud Build" -ForegroundColor Gray
    Write-Host "   Buscando builds recientes..." -ForegroundColor Gray
    Write-Host ""
    
    # Obtener builds recientes
    $builds = & $gcloudPath builds list `
        --project residencias-479706 `
        --limit 5 `
        --format="table(id,status,createTime,logUrl)"
    
    Write-Host $builds
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "4. Para ver logs detallados de un build específico:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Opción A: Desde la consola web (más fácil)" -ForegroundColor Cyan
    Write-Host "   https://console.cloud.google.com/cloud-build/builds?project=residencias-479706" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   Opción B: Desde línea de comandos" -ForegroundColor Cyan
    Write-Host "   gcloud builds log [BUILD_ID] --project=residencias-479706" -ForegroundColor Gray
    Write-Host ""
    
    # Intentar obtener el último build ID
    $ultimoBuild = & $gcloudPath builds list `
        --project residencias-479706 `
        --limit 1 `
        --format="value(id)"
    
    if ($ultimoBuild) {
        Write-Host "   Para ver el último build:" -ForegroundColor Yellow
        Write-Host "   gcloud builds log $ultimoBuild --project=residencias-479706" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   ¿Quieres ver los logs del último build ahora? (S/N): " -NoNewline -ForegroundColor Yellow
        $respuesta = Read-Host
        if ($respuesta -eq 'S' -or $respuesta -eq 's') {
            Write-Host ""
            Write-Host "Mostrando logs del build $ultimoBuild..." -ForegroundColor Cyan
            Write-Host ""
            & $gcloudPath builds log $ultimoBuild --project=residencias-479706
        }
    }
    
} else {
    Write-Host "   ⚠️  No se encontraron revisiones" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "5. Logs del servicio (runtime logs)..." -ForegroundColor Yellow
Write-Host ""

& $gcloudPath run services logs read violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --limit 30

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FIN" -ForegroundColor Cyan
Write-Host ""
Write-Host "Enlaces útiles:" -ForegroundColor Yellow
Write-Host "  - Cloud Build: https://console.cloud.google.com/cloud-build/builds?project=residencias-479706" -ForegroundColor Gray
Write-Host "  - Cloud Run: https://console.cloud.google.com/run?project=residencias-479706" -ForegroundColor Gray
Write-Host ""

