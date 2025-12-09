# Script para configurar Cloud SQL Proxy (Solución Definitiva)
# Este script descarga, configura e inicia Cloud SQL Proxy
# No necesitarás autorizar IPs nunca más

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CONFIGURACIÓN CLOUD SQL PROXY" -ForegroundColor Cyan
Write-Host "  Solución Definitiva - Sin IPs" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Directorio para el proxy
$proxyDir = "$PSScriptRoot\cloud-sql-proxy"
$proxyExe = "$proxyDir\cloud_sql_proxy.exe"

# Crear directorio si no existe
if (-not (Test-Path $proxyDir)) {
    New-Item -ItemType Directory -Path $proxyDir | Out-Null
    Write-Host "✅ Directorio creado: $proxyDir" -ForegroundColor Green
}

# Verificar si ya existe
if (Test-Path $proxyExe) {
    Write-Host "✅ Cloud SQL Proxy ya está instalado" -ForegroundColor Green
    Write-Host "   Ubicación: $proxyExe" -ForegroundColor Gray
} else {
    Write-Host "📥 Descargando Cloud SQL Proxy..." -ForegroundColor Yellow
    
    # URL de descarga para Windows 64-bit
    $downloadUrl = "https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.8.0/cloud-sql-proxy.x64.exe"
    $downloadPath = "$proxyDir\cloud_sql_proxy.exe"
    
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -UseBasicParsing
        Write-Host "✅ Cloud SQL Proxy descargado exitosamente" -ForegroundColor Green
    } catch {
        Write-Host "❌ Error al descargar: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "💡 Descarga manual:" -ForegroundColor Yellow
        Write-Host "   1. Ve a: https://github.com/GoogleCloudPlatform/cloud-sql-proxy/releases" -ForegroundColor Gray
        Write-Host "   2. Descarga: cloud-sql-proxy.x64.exe" -ForegroundColor Gray
        Write-Host "   3. Guárdalo en: $proxyDir" -ForegroundColor Gray
        exit 1
    }
}

Write-Host ""
Write-Host "🔧 Configuración:" -ForegroundColor Cyan
Write-Host ""

# Obtener cadena de conexión
$connectionName = $env:CLOUD_SQL_CONNECTION_NAME
if (-not $connectionName) {
    Write-Host "⚠️  Variable CLOUD_SQL_CONNECTION_NAME no encontrada" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Por favor, ingresa la cadena de conexión de tu instancia Cloud SQL:" -ForegroundColor Yellow
    Write-Host "Formato: PROYECTO:REGION:INSTANCIA" -ForegroundColor Gray
    Write-Host "Ejemplo: residencias-479706:europe-west9:residencias" -ForegroundColor Gray
    Write-Host ""
    $connectionName = Read-Host "Cadena de conexión"
    
    if (-not $connectionName) {
        Write-Host "❌ Cadena de conexión requerida" -ForegroundColor Red
        exit 1
    }
    
    # Guardar en .env
    $envFile = ".env"
    if (Test-Path $envFile) {
        $envContent = Get-Content $envFile -Raw
        if ($envContent -notmatch "CLOUD_SQL_CONNECTION_NAME") {
            Add-Content $envFile "`nCLOUD_SQL_CONNECTION_NAME=$connectionName"
            Write-Host "✅ Guardado en .env" -ForegroundColor Green
        }
    }
}

Write-Host "✅ Cadena de conexión: $connectionName" -ForegroundColor Green
Write-Host ""

# Verificar archivo de credenciales
$credentialsFile = $env:GOOGLE_APPLICATION_CREDENTIALS
if (-not $credentialsFile) {
    # Buscar archivo JSON de credenciales en el directorio actual
    $jsonFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*.json" | Where-Object { $_.Name -like "*residencias*" -or $_.Name -like "*service*" }
    
    if ($jsonFiles.Count -gt 0) {
        $credentialsFile = $jsonFiles[0].FullName
        Write-Host "✅ Credenciales encontradas: $credentialsFile" -ForegroundColor Green
    } else {
        Write-Host "⚠️  No se encontró archivo de credenciales" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Necesitas un archivo JSON de credenciales de servicio de GCP." -ForegroundColor Yellow
        Write-Host "Pasos:" -ForegroundColor Yellow
        Write-Host "1. Ve a: https://console.cloud.google.com/apis/credentials" -ForegroundColor Gray
        Write-Host "2. Crea una cuenta de servicio o usa una existente" -ForegroundColor Gray
        Write-Host "3. Descarga la clave JSON" -ForegroundColor Gray
        Write-Host "4. Guárdala en este directorio con nombre: residencias-*.json" -ForegroundColor Gray
        Write-Host ""
        $credentialsFile = Read-Host "Ruta completa al archivo JSON (o Enter para continuar sin autenticación)"
    }
}

Write-Host ""
Write-Host "🚀 Iniciando Cloud SQL Proxy..." -ForegroundColor Cyan
Write-Host ""

# Comando para iniciar el proxy
$proxyPort = "5432"
$proxyCommand = "& `"$proxyExe`" --port=$proxyPort --address=127.0.0.1 $connectionName"

if ($credentialsFile -and (Test-Path $credentialsFile)) {
    $env:GOOGLE_APPLICATION_CREDENTIALS = $credentialsFile
    Write-Host "   Usando credenciales: $credentialsFile" -ForegroundColor Gray
}

Write-Host "   Puerto local: $proxyPort" -ForegroundColor Gray
Write-Host "   Instancia: $connectionName" -ForegroundColor Gray
Write-Host ""
Write-Host "⚠️  El proxy se ejecutará en segundo plano" -ForegroundColor Yellow
Write-Host "   Presiona Ctrl+C para detenerlo" -ForegroundColor Gray
Write-Host ""

# Iniciar el proxy
try {
    Start-Process -FilePath $proxyExe -ArgumentList "--port=$proxyPort", "--address=127.0.0.1", $connectionName -NoNewWindow
    Write-Host "✅ Cloud SQL Proxy iniciado" -ForegroundColor Green
    Write-Host ""
    Write-Host "💡 Ahora puedes:" -ForegroundColor Cyan
    Write-Host "   1. Actualizar .env: DB_HOST=127.0.0.1" -ForegroundColor Gray
    Write-Host "   2. Iniciar el servidor Flask: python app.py" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "❌ Error al iniciar el proxy: $_" -ForegroundColor Red
    exit 1
}

