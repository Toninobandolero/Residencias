# Script para configurar .env para usar Cloud SQL Proxy
# Ejecuta este script después de setup_cloud_sql_proxy.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CONFIGURAR .ENV PARA CLOUD SQL PROXY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$envFile = ".env"

# Verificar si existe .env
if (-not (Test-Path $envFile)) {
    Write-Host "⚠️  No se encontró .env" -ForegroundColor Yellow
    Write-Host "   Creando archivo .env..." -ForegroundColor Yellow
    New-Item -ItemType File -Path $envFile | Out-Null
}

# Leer contenido actual
$envContent = Get-Content $envFile -Raw -ErrorAction SilentlyContinue
if (-not $envContent) {
    $envContent = ""
}

# Variables a configurar
$updates = @{
    "DB_USE_PROXY" = "true"
    "DB_HOST" = "127.0.0.1"
    "DB_PORT" = "5432"
}

# Obtener cadena de conexión si no está definida
if ($envContent -notmatch "CLOUD_SQL_CONNECTION_NAME") {
    $connectionName = "residencias-479706:europe-west9:residencias"
    Write-Host "ℹ️  Usando cadena de conexión por defecto: $connectionName" -ForegroundColor Cyan
    Write-Host "   (Si es diferente, edita .env manualmente)" -ForegroundColor Gray
    $updates["CLOUD_SQL_CONNECTION_NAME"] = $connectionName
}

# Buscar archivo de credenciales
$jsonFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*residencias*.json" -ErrorAction SilentlyContinue
if ($jsonFiles -and ($envContent -notmatch "GOOGLE_APPLICATION_CREDENTIALS")) {
    $credentialsFile = $jsonFiles[0].Name
    $updates["GOOGLE_APPLICATION_CREDENTIALS"] = $credentialsFile
    Write-Host "✅ Credenciales encontradas: $credentialsFile" -ForegroundColor Green
}

# Actualizar o agregar variables
$lines = if ($envContent) { $envContent -split "`n" } else { @() }
$newLines = @()
$updated = @{}

foreach ($line in $lines) {
    $trimmed = $line.Trim()
    
    # Si es un comentario o línea vacía, mantenerla
    if ($trimmed -eq "" -or $trimmed.StartsWith("#")) {
        $newLines += $line
        continue
    }
    
    # Si es una variable que vamos a actualizar
    $matched = $false
    foreach ($key in $updates.Keys) {
        if ($trimmed -match "^$key\s*=") {
            $newLines += "$key=$($updates[$key])"
            $updated[$key] = $true
            $matched = $true
            break
        }
    }
    
    if (-not $matched) {
        $newLines += $line
    }
}

# Agregar variables que no existían
foreach ($key in $updates.Keys) {
    if (-not $updated[$key]) {
        $newLines += "$key=$($updates[$key])"
    }
}

# Escribir archivo
$newContent = $newLines -join "`n"
Set-Content -Path $envFile -Value $newContent -NoNewline

Write-Host ""
Write-Host "✅ .env actualizado correctamente" -ForegroundColor Green
Write-Host ""
Write-Host "Variables configuradas:" -ForegroundColor Cyan
foreach ($key in $updates.Keys) {
    Write-Host "   $key = $($updates[$key])" -ForegroundColor Gray
}

Write-Host ""
Write-Host "🚀 Próximos pasos:" -ForegroundColor Cyan
Write-Host "   1. Verifica que el archivo de credenciales existe" -ForegroundColor Gray
Write-Host "   2. Ejecuta: .\start_server_with_proxy.ps1" -ForegroundColor Gray
Write-Host ""

