# Script para ver detalles de la revisión fallida
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DETALLES DE REVISIÓN FALLIDA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Obtener última revisión
$revision = & $gcloudPath run revisions list `
    --service violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --limit 1 `
    --format="value(name)"

if ($revision) {
    Write-Host "Última revisión: $revision" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "Estado y condiciones:" -ForegroundColor Cyan
    & $gcloudPath run revisions describe $revision `
        --region europe-west9 `
        --project residencias-479706 `
        --format="yaml(status.conditions)"
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Variables de entorno configuradas:" -ForegroundColor Cyan
    & $gcloudPath run revisions describe $revision `
        --region europe-west9 `
        --project residencias-479706 `
        --format="value(spec.containers[0].env)" | ForEach-Object {
        if ($_ -match 'name:\s*(\w+),value:\s*(.+)') {
            $name = $matches[1]
            $value = $matches[2]
            if ($name -match 'PASSWORD|SECRET') {
                Write-Host "  $name = ***" -ForegroundColor Gray
            } else {
                Write-Host "  $name = $value" -ForegroundColor Gray
            }
        } elseif ($_ -match 'name:\s*(\w+),valueFrom:') {
            Write-Host "  $($matches[1]) = [SECRET]" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "No se encontraron revisiones" -ForegroundColor Red
}

Write-Host ""

