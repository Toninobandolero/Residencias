# Script para ver logs de runtime (cuando el contenedor intenta iniciar)
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LOGS DE RUNTIME (INICIO DEL CONTENEDOR)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Estos logs muestran qué pasa cuando Cloud Run intenta iniciar el contenedor" -ForegroundColor Yellow
Write-Host ""

& $gcloudPath run services logs read violetas-app `
    --region europe-west9 `
    --project residencias-479706 `
    --limit 100

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FIN" -ForegroundColor Cyan
Write-Host ""
Write-Host "Busca errores relacionados con:" -ForegroundColor Yellow
Write-Host "  - ImportError" -ForegroundColor Gray
Write-Host "  - ModuleNotFoundError" -ForegroundColor Gray
Write-Host "  - ValueError (JWT_SECRET_KEY)" -ForegroundColor Gray
Write-Host "  - OperationalError (base de datos)" -ForegroundColor Gray
Write-Host ""

