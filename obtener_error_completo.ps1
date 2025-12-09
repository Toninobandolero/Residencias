# Script para obtener el error completo de Cloud Run
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ERROR COMPLETO DE CLOUD RUN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "1. Buscando logs de error recientes..." -ForegroundColor Yellow
Write-Host ""

# Buscar logs de error de las últimas horas
$logs = & $gcloudPath logging read `
    "resource.type=cloud_run_revision AND resource.labels.service_name=violetas-app AND severity>=ERROR" `
    --project=residencias-479706 `
    --limit=10 `
    --format=json

if ($logs) {
    $logs | ConvertFrom-Json | ForEach-Object {
        Write-Host "Timestamp: $($_.timestamp)" -ForegroundColor Gray
        Write-Host "Severity: $($_.severity)" -ForegroundColor Red
        Write-Host "Message: $($_.textPayload)" -ForegroundColor Yellow
        if ($_.jsonPayload) {
            Write-Host "JSON Payload:" -ForegroundColor Cyan
            $_.jsonPayload | ConvertTo-Json -Depth 10 | Write-Host -ForegroundColor Gray
        }
        Write-Host "----------------------------------------" -ForegroundColor Gray
        Write-Host ""
    }
} else {
    Write-Host "No se encontraron logs de error recientes" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "2. Verificando estado del servicio..." -ForegroundColor Yellow
Write-Host ""

& $gcloudPath run services describe violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --format="yaml(status)"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FIN" -ForegroundColor Cyan
Write-Host ""
Write-Host "Si no ves el error aquí, revisa en la consola web:" -ForegroundColor Yellow
Write-Host "https://console.cloud.google.com/run/detail/europe-west9/violetas-app/logs?project=residencias-479706" -ForegroundColor Gray
Write-Host ""

