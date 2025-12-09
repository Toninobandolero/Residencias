# Script para crear los secrets si no existen
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CREAR SECRETS SI NO EXISTEN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar si existen
Write-Host "1. Verificando secrets existentes..." -ForegroundColor Yellow
$secrets = & $gcloudPath secrets list --project=residencias-479706 --format="value(name)"

$jwtExists = $false
$dbExists = $false

foreach ($secret in $secrets) {
    if ($secret -eq "jwt-secret-key") { $jwtExists = $true }
    if ($secret -eq "db-password") { $dbExists = $true }
}

Write-Host "   jwt-secret-key: $(if ($jwtExists) { '✅ Existe' } else { '❌ No existe' })" -ForegroundColor $(if ($jwtExists) { 'Green' } else { 'Red' })
Write-Host "   db-password: $(if ($dbExists) { '✅ Existe' } else { '❌ No existe' })" -ForegroundColor $(if ($dbExists) { 'Green' } else { 'Red' })
Write-Host ""

# Crear jwt-secret-key si no existe
if (-not $jwtExists) {
    Write-Host "2. Creando jwt-secret-key..." -ForegroundColor Yellow
    Write-Host "   Ingresa la clave secreta para JWT (o presiona Enter para generar una aleatoria): " -NoNewline -ForegroundColor Cyan
    $jwtValue = Read-Host
    
    if (-not $jwtValue) {
        # Generar clave aleatoria
        $jwtValue = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
        Write-Host "   Generada clave aleatoria: $($jwtValue.Substring(0,10))..." -ForegroundColor Gray
    }
    
    $jwtValue | & $gcloudPath secrets create jwt-secret-key --data-file=- --project=residencias-479706 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   ✅ jwt-secret-key creado" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Error al crear jwt-secret-key" -ForegroundColor Red
    }
} else {
    Write-Host "2. jwt-secret-key ya existe, omitiendo..." -ForegroundColor Gray
}

Write-Host ""

# Crear db-password si no existe
if (-not $dbExists) {
    Write-Host "3. Creando db-password..." -ForegroundColor Yellow
    Write-Host "   Ingresa la contraseña de la base de datos PostgreSQL: " -NoNewline -ForegroundColor Cyan
    $dbValue = Read-Host -AsSecureString
    $dbPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($dbValue))
    
    $dbPlainText | & $gcloudPath secrets create db-password --data-file=- --project=residencias-479706 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   ✅ db-password creado" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Error al crear db-password" -ForegroundColor Red
    }
} else {
    Write-Host "3. db-password ya existe, omitiendo..." -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FIN" -ForegroundColor Cyan
Write-Host ""
Write-Host "Ahora otorga permisos con:" -ForegroundColor Yellow
Write-Host "  .\otorgar_permisos_cloud_run.ps1" -ForegroundColor Gray
Write-Host ""

