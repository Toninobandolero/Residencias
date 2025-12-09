# Script para iniciar el servidor Flask
# Uso: .\start_server.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Iniciando Servidor Flask Violetas" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar que el archivo app.py existe
if (-not (Test-Path "app.py")) {
    Write-Host "ERROR: No se encontró app.py en el directorio actual." -ForegroundColor Red
    Write-Host "Asegúrate de ejecutar este script desde el directorio del proyecto." -ForegroundColor Yellow
    exit 1
}

# Verificar que existe el archivo .env
if (-not (Test-Path ".env")) {
    Write-Host "ADVERTENCIA: No se encontró el archivo .env" -ForegroundColor Yellow
    Write-Host "El servidor puede fallar si faltan variables de entorno." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Iniciando servidor Flask..." -ForegroundColor Yellow
Write-Host "  URL: http://localhost:5001" -ForegroundColor Cyan
Write-Host "  (Puerto 5001 - configurable con variable PORT)" -ForegroundColor Gray
Write-Host "  Presiona Ctrl+C para detener el servidor" -ForegroundColor Gray
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Iniciar el servidor
python app.py

