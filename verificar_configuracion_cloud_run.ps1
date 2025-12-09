# Script para verificar la configuración completa de Cloud Run
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VERIFICACIÓN DE CONFIGURACIÓN CLOUD RUN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "1. Información del servicio..." -ForegroundColor Yellow
& $gcloudPath run services describe violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --format="yaml(spec.template.spec.containers[0])" | Select-Object -First 50

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "2. Variables de entorno configuradas..." -ForegroundColor Yellow
& $gcloudPath run services describe violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --format="value(spec.template.spec.containers[0].env)" | ForEach-Object {
    if ($_ -match 'name:\s*(\w+),value:\s*(.+)') {
        $name = $matches[1]
        $value = $matches[2]
        if ($name -eq 'DB_PASSWORD' -or $name -eq 'JWT_SECRET_KEY') {
            Write-Host "  $name = ***SECRET***" -ForegroundColor Gray
        } else {
            Write-Host "  $name = $value" -ForegroundColor Gray
        }
    } elseif ($_ -match 'name:\s*(\w+),valueFrom:') {
        $name = $matches[1]
        Write-Host "  $name = [SECRET]" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "3. Última revisión creada..." -ForegroundColor Yellow
$revision = & $gcloudPath run revisions list `
    --service violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --limit 1 `
    --format="value(name)"

if ($revision) {
    Write-Host "  Revisión: $revision" -ForegroundColor Gray
    Write-Host ""
    Write-Host "4. Estado de la revisión..." -ForegroundColor Yellow
    & $gcloudPath run revisions describe $revision `
        --region europe-west9 `
        --project residencias-479706 `
        --format="yaml(status.conditions)"
} else {
    Write-Host "  ⚠️  No se encontraron revisiones" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FIN" -ForegroundColor Cyan

