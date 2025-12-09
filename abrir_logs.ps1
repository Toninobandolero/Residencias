# Script para abrir los logs directamente en el navegador
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ABRIENDO LOGS EN EL NAVEGADOR" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "1. Abriendo logs del servicio Cloud Run..." -ForegroundColor Yellow
Start-Process "https://console.cloud.google.com/run/detail/europe-west9/violetas-app/logs?project=residencias-479706"

Write-Host ""
Write-Host "2. Abriendo logs del último build..." -ForegroundColor Yellow
Start-Process "https://console.cloud.google.com/cloud-build/builds?project=residencias-479706"

Write-Host ""
Write-Host "✅ Logs abiertos en el navegador" -ForegroundColor Green
Write-Host ""
Write-Host "En los logs del servicio, busca:" -ForegroundColor Yellow
Write-Host "  - Errores al iniciar" -ForegroundColor Gray
Write-Host "  - 'Container import failed'" -ForegroundColor Gray
Write-Host "  - 'ImportError' o 'ModuleNotFoundError'" -ForegroundColor Gray
Write-Host "  - Cualquier mensaje de ERROR" -ForegroundColor Gray
Write-Host ""

