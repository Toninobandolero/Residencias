# Verificar detalles del último build
$buildId = "ab141d4c-ba9e-4a24-bc5b-89dae8b75590"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VERIFICANDO ÚLTIMO BUILD" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Build ID: $buildId" -ForegroundColor Yellow
Write-Host ""
Write-Host "URL del build:" -ForegroundColor Cyan
Write-Host "https://console.cloud.google.com/cloud-build/builds/$buildId?project=residencias-479706" -ForegroundColor Gray
Write-Host ""
Write-Host "Revisa los logs del build para ver si hay errores específicos" -ForegroundColor Yellow
Write-Host ""

# Intentar obtener logs
Write-Host "Obteniendo logs del build..." -ForegroundColor Yellow
gcloud builds log $buildId --project=residencias-479706 2>&1 | Select-String -Pattern "ERROR|FAILED|WARNING|entrypoint|Procfile" -Context 2,2 | Select-Object -First 30

Write-Host ""

