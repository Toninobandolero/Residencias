# Script para habilitar la ejecución de scripts en PowerShell
# Debe ejecutarse como Administrador

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  HABILITAR EJECUCIÓN DE SCRIPTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar si se ejecuta como administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "⚠️  Este script debe ejecutarse como Administrador" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Opciones:" -ForegroundColor Cyan
    Write-Host "1. Ejecutar PowerShell como Administrador y ejecutar:" -ForegroundColor Gray
    Write-Host "   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "2. O usar el método alternativo (ver abajo)" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

Write-Host "Política actual: " -NoNewline
$currentPolicy = Get-ExecutionPolicy
Write-Host $currentPolicy -ForegroundColor Yellow
Write-Host ""

Write-Host "Cambiando política a RemoteSigned (solo para el usuario actual)..." -ForegroundColor Yellow
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

Write-Host ""
Write-Host "✅ Política actualizada" -ForegroundColor Green
Write-Host ""
Write-Host "Nueva política: " -NoNewline
$newPolicy = Get-ExecutionPolicy
Write-Host $newPolicy -ForegroundColor Green
Write-Host ""
Write-Host "Ahora puedes ejecutar scripts locales." -ForegroundColor Cyan

