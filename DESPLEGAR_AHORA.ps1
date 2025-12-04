# Script completo de despliegue a Cloud Run
# Ejecuta este script DESPUES de instalar Google Cloud SDK

param(
    [string]$JWT_SECRET = "",
    [string]$DB_PASSWORD = ""
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DESPLIEGUE A CLOUD RUN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Encontrar gcloud
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"
if (-not (Test-Path $gcloudPath)) {
    $gcloudPath = "$env:ProgramFiles\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"
}
if (-not (Test-Path $gcloudPath)) {
    Write-Host "ERROR: gcloud no encontrado" -ForegroundColor Red
    Write-Host "Instala Google Cloud SDK desde: https://cloud.google.com/sdk/docs/install" -ForegroundColor Yellow
    exit 1
}

# Funcion para ejecutar gcloud
function Invoke-GCloud {
    param([string[]]$Arguments)
    & $gcloudPath $Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Error ejecutando gcloud: $($Arguments -join ' ')"
    }
}

# Configuracion
$PROJECT_ID = "residencias-479706"
$REGION = "europe-west9"
$SERVICE_NAME = "violetas-app"
$CLOUD_SQL_INSTANCE = "residencias-479706:europe-west9:residencias"

# 1. Autenticacion
Write-Host "1. Verificando autenticacion..." -ForegroundColor Yellow
try {
    $account = Invoke-GCloud @("config", "get-value", "account") 2>&1 | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($account)) {
        Write-Host "   Iniciando autenticacion..." -ForegroundColor Yellow
        Write-Host "   Se abrira una ventana del navegador para autenticarte" -ForegroundColor Cyan
        Invoke-GCloud @("auth", "login")
    } else {
        Write-Host "   [OK] Autenticado como: $account" -ForegroundColor Green
    }
} catch {
    Write-Host "   Iniciando autenticacion..." -ForegroundColor Yellow
    Invoke-GCloud @("auth", "login")
}

# 2. Configurar proyecto
Write-Host ""
Write-Host "2. Configurando proyecto..." -ForegroundColor Yellow
Invoke-GCloud @("config", "set", "project", $PROJECT_ID)
Write-Host "   [OK] Proyecto configurado: $PROJECT_ID" -ForegroundColor Green

# 3. Habilitar APIs
Write-Host ""
Write-Host "3. Habilitando APIs..." -ForegroundColor Yellow
Invoke-GCloud @("services", "enable", "run.googleapis.com", "--quiet")
Invoke-GCloud @("services", "enable", "cloudbuild.googleapis.com", "--quiet")
Invoke-GCloud @("services", "enable", "secretmanager.googleapis.com", "--quiet")
Invoke-GCloud @("services", "enable", "artifactregistry.googleapis.com", "--quiet")
Write-Host "   [OK] APIs habilitadas" -ForegroundColor Green

# 4. Crear Artifact Registry
Write-Host ""
Write-Host "4. Verificando Artifact Registry..." -ForegroundColor Yellow
try {
    $repoExists = Invoke-GCloud @("artifacts", "repositories", "describe", "violetas-app", "--location=$REGION", "--format=value(name)") 2>&1
    Write-Host "   [OK] Repositorio existe" -ForegroundColor Green
} catch {
    Write-Host "   Creando repositorio..." -ForegroundColor Yellow
    Invoke-GCloud @("artifacts", "repositories", "create", "violetas-app", "--repository-format=docker", "--location=$REGION", "--description=Repositorio Docker para Violetas App", "--quiet")
    Write-Host "   [OK] Repositorio creado" -ForegroundColor Green
}

# 5. Crear secretos
Write-Host ""
Write-Host "5. Configurando Secret Manager..." -ForegroundColor Yellow

# JWT Secret
try {
    Invoke-GCloud @("secrets", "describe", "jwt-secret-key", "--format=value(name)") | Out-Null
    Write-Host "   [OK] jwt-secret-key existe" -ForegroundColor Green
} catch {
    if ([string]::IsNullOrWhiteSpace($JWT_SECRET)) {
        Write-Host "   [ADVERTENCIA] jwt-secret-key no existe" -ForegroundColor Yellow
        Write-Host "   Creando con valor por defecto (CAMBIA ESTO EN PRODUCCION!)" -ForegroundColor Yellow
        $JWT_SECRET = "CAMBIAR_ESTA_CLAVE_EN_PRODUCCION_" + [System.Guid]::NewGuid().ToString()
    }
    $JWT_SECRET | Invoke-GCloud @("secrets", "create", "jwt-secret-key", "--data-file=-")
    Write-Host "   [OK] jwt-secret-key creado" -ForegroundColor Green
}

# DB Password
try {
    Invoke-GCloud @("secrets", "describe", "db-password", "--format=value(name)") | Out-Null
    Write-Host "   [OK] db-password existe" -ForegroundColor Green
} catch {
    if ([string]::IsNullOrWhiteSpace($DB_PASSWORD)) {
        Write-Host "   [ERROR] db-password no existe y no se proporciono contraseña" -ForegroundColor Red
        Write-Host "   Ejecuta el script con: .\DESPLEGAR_AHORA.ps1 -DB_PASSWORD 'TU_CONTRASEÑA'" -ForegroundColor Yellow
        exit 1
    }
    $DB_PASSWORD | Invoke-GCloud @("secrets", "create", "db-password", "--data-file=-")
    Write-Host "   [OK] db-password creado" -ForegroundColor Green
}

# 6. Desplegar
Write-Host ""
Write-Host "6. Desplegando aplicacion..." -ForegroundColor Yellow
Write-Host "   Esto puede tardar varios minutos..." -ForegroundColor Gray
Write-Host ""

Invoke-GCloud @("run", "deploy", $SERVICE_NAME, `
    "--source", ".", `
    "--region", $REGION, `
    "--platform", "managed", `
    "--allow-unauthenticated", `
    "--add-cloudsql-instances", $CLOUD_SQL_INSTANCE, `
    "--set-env-vars", "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=$CLOUD_SQL_INSTANCE", `
    "--set-secrets", "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest", `
    "--memory", "1Gi", `
    "--cpu", "1", `
    "--timeout", "300", `
    "--max-instances", "10", `
    "--min-instances", "1")

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  DESPLIEGUE COMPLETADO" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

$serviceUrl = Invoke-GCloud @("run", "services", "describe", $SERVICE_NAME, "--region", $REGION, "--format=value(status.url)")
Write-Host "URL de la aplicacion: $serviceUrl" -ForegroundColor Cyan
Write-Host ""
Write-Host "Abre esta URL en tu navegador para acceder a la aplicacion" -ForegroundColor Yellow

