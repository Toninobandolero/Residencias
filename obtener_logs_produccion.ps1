# Script para obtener y analizar logs de Cloud Run
# Uso: .\obtener_logs_produccion.ps1

$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LOGS DE PRODUCCIÓN - CLOUD RUN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar que gcloud está disponible
if (-not (Test-Path $gcloudPath)) {
    Write-Host "ERROR: Google Cloud SDK no encontrado" -ForegroundColor Red
    Write-Host "Instala desde: https://cloud.google.com/sdk/docs/install" -ForegroundColor Yellow
    exit 1
}

Write-Host "1. Obteniendo logs recientes (últimas 50 líneas)..." -ForegroundColor Yellow
Write-Host ""

& $gcloudPath run services logs read violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --limit 50

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "2. Obteniendo información de la revisión más reciente..." -ForegroundColor Yellow
Write-Host ""

& $gcloudPath run revisions describe violetas-app-00007-g4w `
    --region europe-west9 `
    --project residencias-479706 `
    --format="yaml(status.conditions)"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "3. Verificando estado del servicio..." -ForegroundColor Yellow
Write-Host ""

& $gcloudPath run services describe violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --format="table(status.conditions.type,status.conditions.status,status.conditions.message)"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "4. Verificando variables de entorno configuradas..." -ForegroundColor Yellow
Write-Host ""

& $gcloudPath run services describe violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --format="value(spec.template.spec.containers[0].env)" | ForEach-Object {
    if ($_ -match 'name:\s*(\w+),value:\s*(.+)') {
        $name = $matches[1]
        $value = $matches[2]
        if ($name -eq 'DB_PASSWORD' -or $name -eq 'JWT_SECRET_KEY') {
            Write-Host "  $name = ***OCULTO***" -ForegroundColor Gray
        } else {
            Write-Host "  $name = $value" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "5. Verificando secrets configurados..." -ForegroundColor Yellow
Write-Host ""

& $gcloudPath run services describe violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --format="value(spec.template.spec.containers[0].env)" | Select-String -Pattern "secret" | ForEach-Object {
    Write-Host "  $_" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FIN DE LOGS" -ForegroundColor Cyan
Write-Host ""
Write-Host "Para ver logs en tiempo real:" -ForegroundColor Yellow
Write-Host "  gcloud run services logs tail violetas-app --region europe-west9 --project residencias-479706" -ForegroundColor Gray
Write-Host ""

