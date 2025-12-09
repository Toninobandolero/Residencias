# Script para reiniciar el servidor Flask
# Uso: .\restart_server.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Reiniciando Servidor Flask Violetas" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Detener procesos de Python que estén ejecutando app.py
Write-Host "Deteniendo procesos existentes..." -ForegroundColor Yellow

# Buscar procesos de Python que tengan app.py en la línea de comandos
$processes = Get-WmiObject Win32_Process -Filter "name='python.exe' OR name='pythonw.exe'" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*app.py*"
}

if ($processes) {
    foreach ($proc in $processes) {
        try {
            $pid = $proc.ProcessId
            Write-Host "  Deteniendo proceso PID: $pid" -ForegroundColor Gray
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  No se pudo detener proceso $pid" -ForegroundColor Red
        }
    }
    Start-Sleep -Seconds 2
    Write-Host "  Procesos detenidos." -ForegroundColor Green
} else {
    Write-Host "  No hay procesos de Python ejecutando app.py." -ForegroundColor Gray
}

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

# Iniciar el servidor
Write-Host "Iniciando servidor Flask..." -ForegroundColor Yellow
Write-Host "  URL: http://localhost:5000" -ForegroundColor Cyan
Write-Host "  Presiona Ctrl+C para detener el servidor" -ForegroundColor Gray
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Iniciar el servidor en la misma terminal (logs visibles)
python app.py

