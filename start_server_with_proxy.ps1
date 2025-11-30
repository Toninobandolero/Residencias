# Script para iniciar el servidor Flask con Cloud SQL Proxy
# Solución definitiva - No requiere autorizar IPs

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  INICIANDO SERVIDOR CON CLOUD SQL PROXY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar que existe app.py
if (-not (Test-Path "app.py")) {
    Write-Host "ERROR: No se encontró app.py" -ForegroundColor Red
    exit 1
}

# Verificar .env
if (-not (Test-Path ".env")) {
    Write-Host "ADVERTENCIA: No se encontró .env" -ForegroundColor Yellow
}

# Directorio del proxy
$proxyDir = "$PSScriptRoot\cloud-sql-proxy"
$proxyExe = "$proxyDir\cloud_sql_proxy.exe"

# Verificar si el proxy está instalado
if (-not (Test-Path $proxyExe)) {
    Write-Host "⚠️  Cloud SQL Proxy no está instalado" -ForegroundColor Yellow
    Write-Host "   Ejecutando configuración..." -ForegroundColor Yellow
    Write-Host ""
    & "$PSScriptRoot\setup_cloud_sql_proxy.ps1"
    
    if (-not (Test-Path $proxyExe)) {
        Write-Host ""
        Write-Host "❌ No se pudo instalar Cloud SQL Proxy" -ForegroundColor Red
        Write-Host "   Por favor, ejecuta manualmente: .\setup_cloud_sql_proxy.ps1" -ForegroundColor Yellow
        exit 1
    }
}

# Cargar variables de entorno desde .env
if (Test-Path ".env") {
    Get-Content ".env" | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]*)\s*=\s*(.*)\s*$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            [Environment]::SetEnvironmentVariable($key, $value, "Process")
        }
    }
}

# Obtener cadena de conexión
$connectionName = $env:CLOUD_SQL_CONNECTION_NAME
if (-not $connectionName) {
    # Intentar detectar desde el nombre del proyecto
    $connectionName = "residencias-479706:europe-west9:residencias"
    Write-Host "⚠️  CLOUD_SQL_CONNECTION_NAME no definido" -ForegroundColor Yellow
    Write-Host "   Usando: $connectionName" -ForegroundColor Gray
    Write-Host "   (Agrega CLOUD_SQL_CONNECTION_NAME a .env si es diferente)" -ForegroundColor Gray
}

# Verificar archivo de credenciales
$credentialsFile = $env:GOOGLE_APPLICATION_CREDENTIALS
if (-not $credentialsFile) {
    # Buscar archivo JSON en el directorio
    $jsonFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*residencias*.json" -ErrorAction SilentlyContinue
    if ($jsonFiles) {
        $credentialsFile = $jsonFiles[0].FullName
        $env:GOOGLE_APPLICATION_CREDENTIALS = $credentialsFile
        Write-Host "✅ Credenciales encontradas: $(Split-Path $credentialsFile -Leaf)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  No se encontró archivo de credenciales" -ForegroundColor Yellow
        Write-Host "   El proxy puede fallar sin credenciales" -ForegroundColor Yellow
    }
}

# Configurar para usar proxy
$env:DB_USE_PROXY = "true"
if ($env:DB_HOST -ne "127.0.0.1") {
    Write-Host "ℹ️  Configurando DB_HOST para usar proxy (127.0.0.1)" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "🚀 Iniciando Cloud SQL Proxy..." -ForegroundColor Cyan
Write-Host "   Instancia: $connectionName" -ForegroundColor Gray
Write-Host "   Puerto: 5432" -ForegroundColor Gray
Write-Host ""

# Iniciar proxy en segundo plano
$proxyProcess = Start-Process -FilePath $proxyExe -ArgumentList "--port=5432", "--address=127.0.0.1", $connectionName -PassThru -WindowStyle Hidden

# Esperar un momento para que el proxy inicie
Start-Sleep -Seconds 3

# Verificar que el proxy está corriendo
if (-not $proxyProcess.HasExited) {
    Write-Host "✅ Cloud SQL Proxy iniciado (PID: $($proxyProcess.Id))" -ForegroundColor Green
} else {
    Write-Host "❌ El proxy se detuvo inmediatamente" -ForegroundColor Red
    Write-Host "   Revisa los logs o ejecuta el proxy manualmente" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "🚀 Iniciando servidor Flask..." -ForegroundColor Cyan
Write-Host "   URL: http://localhost:5000" -ForegroundColor Gray
Write-Host "   Presiona Ctrl+C para detener ambos servicios" -ForegroundColor Gray
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Función para limpiar al salir
function Cleanup {
    Write-Host ""
    Write-Host "🛑 Deteniendo servicios..." -ForegroundColor Yellow
    if ($proxyProcess -and -not $proxyProcess.HasExited) {
        Stop-Process -Id $proxyProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host "   ✅ Cloud SQL Proxy detenido" -ForegroundColor Green
    }
}

# Registrar función de limpieza
Register-EngineEvent PowerShell.Exiting -Action { Cleanup } | Out-Null

# Iniciar servidor Flask
try {
    python app.py
} finally {
    Cleanup
}

