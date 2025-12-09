# Script de despliegue MEJORADO con verificaciones y manejo de errores
# Uso: .\deploy_mejorado.ps1

$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DESPLIEGUE MEJORADO A CLOUD RUN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar que gcloud está disponible
if (-not (Test-Path $gcloudPath)) {
    Write-Host "ERROR: Google Cloud SDK no encontrado" -ForegroundColor Red
    Write-Host "Instala desde: https://cloud.google.com/sdk/docs/install" -ForegroundColor Yellow
    exit 1
}

# Verificar archivos críticos
Write-Host "1. Verificando archivos críticos..." -ForegroundColor Yellow
$archivos_criticos = @('app.py', 'Procfile', 'requirements.txt', 'runtime.txt')
$faltan_archivos = $false

foreach ($archivo in $archivos_criticos) {
    if (Test-Path $archivo) {
        Write-Host "   ✅ $archivo" -ForegroundColor Green
    } else {
        Write-Host "   ❌ FALTA: $archivo" -ForegroundColor Red
        $faltan_archivos = $true
    }
}

if ($faltan_archivos) {
    Write-Host ""
    Write-Host "ERROR: Faltan archivos críticos. No se puede desplegar." -ForegroundColor Red
    exit 1
}

Write-Host ""

# Verificar sintaxis de Python
Write-Host "2. Verificando sintaxis de app.py..." -ForegroundColor Yellow
try {
    $resultado = python -m py_compile app.py 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   ✅ Sintaxis válida" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Error de sintaxis:" -ForegroundColor Red
        Write-Host $resultado -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "   ⚠️  No se pudo verificar sintaxis (python no disponible)" -ForegroundColor Yellow
}

Write-Host ""

# Verificar que los secrets existen
Write-Host "3. Verificando secrets en Secret Manager..." -ForegroundColor Yellow
$secrets = @('jwt-secret-key', 'db-password')
$secrets_ok = $true

foreach ($secret in $secrets) {
    $existe = & $gcloudPath secrets describe $secret --project=residencias-479706 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   ✅ $secret existe" -ForegroundColor Green
    } else {
        Write-Host "   ❌ $secret NO existe" -ForegroundColor Red
        Write-Host "      Crear con: gcloud secrets create $secret --data-file=-" -ForegroundColor Yellow
        $secrets_ok = $false
    }
}

if (-not $secrets_ok) {
    Write-Host ""
    Write-Host "ADVERTENCIA: Algunos secrets no existen. El despliegue puede fallar." -ForegroundColor Yellow
    Write-Host "¿Continuar de todas formas? (S/N): " -NoNewline -ForegroundColor Yellow
    $respuesta = Read-Host
    if ($respuesta -ne 'S' -and $respuesta -ne 's') {
        exit 1
    }
}

Write-Host ""

# Desplegar
Write-Host "4. Desplegando a Cloud Run..." -ForegroundColor Yellow
Write-Host "   Esto puede tardar varios minutos..." -ForegroundColor Gray
Write-Host ""

$deployOutput = & $gcloudPath run deploy violetas-app `
    --source . `
    --region europe-west9 `
    --platform managed `
    --allow-unauthenticated `
    --add-cloudsql-instances residencias-479706:europe-west9:residencias `
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias,GCS_BUCKET_NAME=violetas-documentos" `
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" `
    --memory 2Gi `
    --cpu 2 `
    --timeout 300 `
    --max-instances 10 `
    --min-instances 0 `
    --project=residencias-479706 2>&1

$deployOutput | Write-Host

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ✅ DESPLIEGUE EXITOSO" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    $url = & $gcloudPath run services describe violetas-app --region europe-west9 --format="value(status.url)" --project=residencias-479706
    Write-Host "URL del servicio: $url" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "5. Verificando health check..." -ForegroundColor Yellow
    try {
        $healthResponse = Invoke-WebRequest -Uri "$url/health" -Method GET -TimeoutSec 10 -ErrorAction SilentlyContinue
        if ($healthResponse.StatusCode -eq 200) {
            Write-Host "   ✅ Health check OK" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Health check retornó código: $($healthResponse.StatusCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   ⚠️  No se pudo verificar health check: $_" -ForegroundColor Yellow
        Write-Host "   Esto es normal si el servicio está iniciando. Espera unos segundos." -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Para ver logs:" -ForegroundColor Yellow
    Write-Host "  .\obtener_logs_produccion.ps1" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Para ver logs en tiempo real:" -ForegroundColor Yellow
    Write-Host "  gcloud run services logs tail violetas-app --region europe-west9 --project residencias-479706" -ForegroundColor Gray
    
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  ❌ ERROR EN EL DESPLIEGUE" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Revisa los logs arriba para más detalles." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Para obtener más información:" -ForegroundColor Yellow
    Write-Host "  .\obtener_logs_produccion.ps1" -ForegroundColor Gray
    Write-Host "  https://console.cloud.google.com/run?project=residencias-479706" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

