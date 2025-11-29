# Script PowerShell para crear backup de la base de datos
# Uso: .\backup.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BACKUP DE BASE DE DATOS - Violetas" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

python backup_database.py

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ Backup completado exitosamente" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "❌ Error al crear backup" -ForegroundColor Red
    Write-Host "Asegúrate de tener pg_dump instalado" -ForegroundColor Yellow
}

