$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "Verificando estado del servicio..." -ForegroundColor Yellow
Write-Host ""

try {
    $url = & $gcloudPath run services describe violetas-app --region europe-west9 --format="value(status.url)" --project=residencias-479706 2>&1
    
    if ($url -and $url -notmatch "ERROR" -and $url -notmatch "not found") {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "URL DE TU APLICACION:" -ForegroundColor Cyan
        Write-Host $url -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Abre esta URL en tu navegador" -ForegroundColor Green
    } else {
        Write-Host "El servicio aun no esta disponible o el despliegue fallo" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Verifica el estado en:" -ForegroundColor Cyan
        Write-Host "https://console.cloud.google.com/run?project=residencias-479706" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "O ejecuta:" -ForegroundColor Cyan
        Write-Host "& `$gcloudPath run services list --region europe-west9" -ForegroundColor Gray
    }
} catch {
    Write-Host "Error al obtener la URL: $_" -ForegroundColor Red
}

