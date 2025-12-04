# Script de despliegue automatizado para Cloud Run
# Uso: .\deploy.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DESPLIEGUE A CLOUD RUN - VIOLETAS APP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar que gcloud está instalado
try {
    $gcloudVersion = gcloud --version 2>&1 | Select-Object -First 1
    Write-Host "✓ Google Cloud SDK encontrado: $gcloudVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ ERROR: Google Cloud SDK no está instalado" -ForegroundColor Red
    Write-Host "   Instala desde: https://cloud.google.com/sdk/docs/install" -ForegroundColor Yellow
    exit 1
}

# Verificar que estamos autenticados
try {
    $currentAccount = gcloud config get-value account 2>&1
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($currentAccount)) {
        Write-Host "⚠️  No hay cuenta autenticada. Iniciando autenticación..." -ForegroundColor Yellow
        gcloud auth login
    } else {
        Write-Host "✓ Autenticado como: $currentAccount" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ ERROR al verificar autenticación" -ForegroundColor Red
    exit 1
}

# Configurar proyecto
$PROJECT_ID = "residencias-479706"
$REGION = "europe-west9"
$SERVICE_NAME = "violetas-app"
$CLOUD_SQL_INSTANCE = "residencias-479706:europe-west9:residencias"

Write-Host ""
Write-Host "Configuración:" -ForegroundColor Cyan
Write-Host "  Proyecto: $PROJECT_ID" -ForegroundColor Gray
Write-Host "  Región: $REGION" -ForegroundColor Gray
Write-Host "  Servicio: $SERVICE_NAME" -ForegroundColor Gray
Write-Host "  Cloud SQL: $CLOUD_SQL_INSTANCE" -ForegroundColor Gray
Write-Host ""

# Verificar que el proyecto está configurado
$currentProject = gcloud config get-value project 2>&1
if ($currentProject -ne $PROJECT_ID) {
    Write-Host "⚠️  Configurando proyecto a $PROJECT_ID..." -ForegroundColor Yellow
    gcloud config set project $PROJECT_ID
}

# Habilitar APIs necesarias
Write-Host "Habilitando APIs necesarias..." -ForegroundColor Yellow
gcloud services enable run.googleapis.com --quiet
gcloud services enable cloudbuild.googleapis.com --quiet
gcloud services enable secretmanager.googleapis.com --quiet
gcloud services enable artifactregistry.googleapis.com --quiet
Write-Host "✓ APIs habilitadas" -ForegroundColor Green

# Verificar que Artifact Registry existe
Write-Host ""
Write-Host "Verificando Artifact Registry..." -ForegroundColor Yellow
$repoExists = gcloud artifacts repositories describe violetas-app --location=$REGION --format="value(name)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  Creando repositorio Artifact Registry..." -ForegroundColor Yellow
    gcloud artifacts repositories create violetas-app `
        --repository-format=docker `
        --location=$REGION `
        --description="Repositorio de imágenes Docker para Violetas App"
    Write-Host "✓ Repositorio creado" -ForegroundColor Green
} else {
    Write-Host "✓ Repositorio existe" -ForegroundColor Green
}

# Verificar que los secretos existen
Write-Host ""
Write-Host "Verificando secretos en Secret Manager..." -ForegroundColor Yellow
$secrets = @("jwt-secret-key", "db-password")
foreach ($secret in $secrets) {
    $secretExists = gcloud secrets describe $secret --format="value(name)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️  ADVERTENCIA: El secreto '$secret' no existe" -ForegroundColor Yellow
        Write-Host "   Créalo con: echo -n 'valor' | gcloud secrets create $secret --data-file=-" -ForegroundColor Gray
    } else {
        Write-Host "✓ Secreto '$secret' existe" -ForegroundColor Green
    }
}

# Preguntar si continuar
Write-Host ""
$confirm = Read-Host "¿Continuar con el despliegue? (S/N)"
if ($confirm -ne "S" -and $confirm -ne "s" -and $confirm -ne "Y" -and $confirm -ne "y") {
    Write-Host "Despliegue cancelado." -ForegroundColor Yellow
    exit 0
}

# Desplegar a Cloud Run
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CONSTRUYENDO Y DESPLEGANDO..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

gcloud run deploy $SERVICE_NAME `
    --source . `
    --region $REGION `
    --platform managed `
    --allow-unauthenticated `
    --add-cloudsql-instances $CLOUD_SQL_INSTANCE `
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=$CLOUD_SQL_INSTANCE" `
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" `
    --memory 1Gi `
    --cpu 1 `
    --timeout 300 `
    --max-instances 10 `
    --min-instances 1

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ✓ DESPLIEGUE COMPLETADO" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    # Obtener URL del servicio
    $serviceUrl = gcloud run services describe $SERVICE_NAME --region $REGION --format="value(status.url)"
    Write-Host "URL del servicio: $serviceUrl" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Próximos pasos:" -ForegroundColor Yellow
    Write-Host "  1. Verificar logs: gcloud logging read 'resource.type=cloud_run_revision AND resource.labels.service_name=$SERVICE_NAME' --limit 50" -ForegroundColor Gray
    Write-Host "  2. Probar la aplicación: $serviceUrl" -ForegroundColor Gray
    Write-Host "  3. Configurar dominio personalizado (opcional)" -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "❌ ERROR en el despliegue" -ForegroundColor Red
    Write-Host "   Revisa los mensajes de error arriba" -ForegroundColor Yellow
    exit 1
}

