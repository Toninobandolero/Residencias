# Script para verificar que todo esta listo para produccion
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VERIFICACION PRE-DESPLIEGUE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$errores = 0

# 1. Verificar Google Cloud SDK
Write-Host "1. Verificando Google Cloud SDK..." -ForegroundColor Yellow
try {
    $gcloudVersion = gcloud --version 2>&1 | Select-Object -First 1
    Write-Host "   [OK] Google Cloud SDK instalado: $gcloudVersion" -ForegroundColor Green
} catch {
    Write-Host "   [ERROR] Google Cloud SDK NO esta instalado" -ForegroundColor Red
    Write-Host "      Instala desde: https://cloud.google.com/sdk/docs/install" -ForegroundColor Yellow
    $errores++
}

# 2. Verificar autenticacion
Write-Host ""
Write-Host "2. Verificando autenticacion..." -ForegroundColor Yellow
try {
    $account = gcloud config get-value account 2>&1
    if ($LASTEXITCODE -eq 0 -and $account) {
        Write-Host "   [OK] Autenticado como: $account" -ForegroundColor Green
    } else {
        Write-Host "   [ADVERTENCIA] No autenticado. Ejecuta: gcloud auth login" -ForegroundColor Yellow
        $errores++
    }
} catch {
    Write-Host "   [ERROR] Error al verificar autenticacion" -ForegroundColor Red
    $errores++
}

# 3. Verificar proyecto
Write-Host ""
Write-Host "3. Verificando proyecto..." -ForegroundColor Yellow
$PROJECT_ID = "residencias-479706"
$currentProject = gcloud config get-value project 2>&1
if ($LASTEXITCODE -eq 0 -and $currentProject -eq $PROJECT_ID) {
    Write-Host "   [OK] Proyecto configurado: $PROJECT_ID" -ForegroundColor Green
} else {
    Write-Host "   [ADVERTENCIA] Proyecto no configurado. Ejecuta: gcloud config set project $PROJECT_ID" -ForegroundColor Yellow
    $errores++
}

# 4. Verificar APIs habilitadas
Write-Host ""
Write-Host "4. Verificando APIs habilitadas..." -ForegroundColor Yellow
$apis = @("run.googleapis.com", "cloudbuild.googleapis.com", "secretmanager.googleapis.com", "artifactregistry.googleapis.com")
foreach ($api in $apis) {
    $enabled = gcloud services list --enabled --filter="name:$api" --format="value(name)" 2>&1
    if ($enabled -like "*$api*") {
        Write-Host "   [OK] $api habilitada" -ForegroundColor Green
    } else {
        Write-Host "   [ADVERTENCIA] $api NO habilitada" -ForegroundColor Yellow
    }
}

# 5. Verificar Secret Manager
Write-Host ""
Write-Host "5. Verificando Secret Manager..." -ForegroundColor Yellow
$secrets = @("jwt-secret-key", "db-password")
foreach ($secret in $secrets) {
    $exists = gcloud secrets describe $secret --format="value(name)" 2>&1
    if ($LASTEXITCODE -eq 0 -and $exists) {
        Write-Host "   [OK] Secreto '$secret' existe" -ForegroundColor Green
    } else {
        Write-Host "   [ERROR] Secreto '$secret' NO existe" -ForegroundColor Red
        Write-Host "      Crealo con: echo -n 'valor' | gcloud secrets create $secret --data-file=-" -ForegroundColor Yellow
        $errores++
    }
}

# 6. Verificar archivos necesarios
Write-Host ""
Write-Host "6. Verificando archivos del proyecto..." -ForegroundColor Yellow
$archivos = @("Dockerfile", "requirements.txt", "app.py", "db_connector.py", "static/index.html")
foreach ($archivo in $archivos) {
    if (Test-Path $archivo) {
        Write-Host "   [OK] $archivo existe" -ForegroundColor Green
    } else {
        Write-Host "   [ERROR] $archivo NO existe" -ForegroundColor Red
        $errores++
    }
}

# 7. Verificar Cloud SQL
Write-Host ""
Write-Host "7. Verificando Cloud SQL..." -ForegroundColor Yellow
$instance = gcloud sql instances describe residencias --format="value(name)" 2>&1
if ($LASTEXITCODE -eq 0 -and $instance) {
    Write-Host "   [OK] Instancia Cloud SQL encontrada: $instance" -ForegroundColor Green
} else {
    Write-Host "   [ADVERTENCIA] No se pudo verificar Cloud SQL" -ForegroundColor Yellow
}

# Resumen
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
if ($errores -eq 0) {
    Write-Host "  [OK] TODO LISTO PARA DESPLEGAR" -ForegroundColor Green
    Write-Host "  Ejecuta: .\deploy.ps1" -ForegroundColor Cyan
} else {
    Write-Host "  [ADVERTENCIA] HAY $errores ERROR(ES) QUE CORREGIR" -ForegroundColor Yellow
    Write-Host "  Revisa los mensajes arriba" -ForegroundColor Yellow
}
Write-Host "========================================" -ForegroundColor Cyan

