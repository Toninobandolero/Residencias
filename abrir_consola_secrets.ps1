# Script para abrir las páginas de secrets en la consola web
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ABRIENDO CONSOLA WEB - SECRETS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Abriendo páginas en el navegador..." -ForegroundColor Yellow
Write-Host ""

# Abrir jwt-secret-key
Write-Host "1. jwt-secret-key..." -ForegroundColor Cyan
Start-Process "https://console.cloud.google.com/security/secret-manager/secret/jwt-secret-key?project=residencias-479706"

Start-Sleep -Seconds 2

# Abrir db-password
Write-Host "2. db-password..." -ForegroundColor Cyan
Start-Process "https://console.cloud.google.com/security/secret-manager/secret/db-password?project=residencias-479706"

Start-Sleep -Seconds 2

# Abrir IAM para Cloud SQL y Storage
Write-Host "3. IAM (para Cloud SQL y Storage)..." -ForegroundColor Cyan
Start-Process "https://console.cloud.google.com/iam-admin/iam?project=residencias-479706"

Write-Host ""
Write-Host "✅ Páginas abiertas en el navegador" -ForegroundColor Green
Write-Host ""
Write-Host "INSTRUCCIONES:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Para cada SECRET:" -ForegroundColor Cyan
Write-Host "  1. Ve a la pestaña 'PERMISOS'" -ForegroundColor Gray
Write-Host "  2. Click en 'AGREGAR PRINCIPAL'" -ForegroundColor Gray
Write-Host "  3. Pega: 621063984498-compute@developer.gserviceaccount.com" -ForegroundColor Gray
Write-Host "  4. Rol: 'Acceso a Secret Manager Secret Accessor'" -ForegroundColor Gray
Write-Host "  5. Click en 'GUARDAR'" -ForegroundColor Gray
Write-Host ""
Write-Host "Para Cloud SQL y Storage (en IAM):" -ForegroundColor Cyan
Write-Host "  1. Busca la cuenta: 621063984498-compute@developer.gserviceaccount.com" -ForegroundColor Gray
Write-Host "  2. Click en editar (lápiz)" -ForegroundColor Gray
Write-Host "  3. Agrega rol: 'Cliente de Cloud SQL'" -ForegroundColor Gray
Write-Host "  4. Agrega rol: 'Administrador de objetos de Storage'" -ForegroundColor Gray
Write-Host "  5. Click en 'GUARDAR'" -ForegroundColor Gray
Write-Host ""

