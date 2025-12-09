# Script para detener el servidor Flask
# Uso: .\stop_server.ps1

Write-Host "Deteniendo servidor Flask..." -ForegroundColor Yellow

$processes = Get-Process python -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*app.py*" -or $_.Path -like "*python*"
}

if ($processes) {
    foreach ($proc in $processes) {
        try {
            Write-Host "  Deteniendo proceso PID: $($proc.Id)" -ForegroundColor Gray
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  No se pudo detener proceso $($proc.Id)" -ForegroundColor Red
        }
    }
    Write-Host "Servidor detenido." -ForegroundColor Green
} else {
    Write-Host "No hay procesos de Python ejecutándose." -ForegroundColor Gray
}

