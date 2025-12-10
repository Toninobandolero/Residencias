# Script completo para verificar la configuración de GCP
$gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

# Si no está en Windows, usar gcloud directamente
if (-not (Test-Path $gcloudPath)) {
    $gcloudPath = "gcloud"
}

$PROJECT_ID = "residencias-479706"
$REGION = "europe-west9"
$SERVICE = "violetas-app"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VERIFICACIÓN COMPLETA DE GCP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verificar autenticación
Write-Host "1. Verificando autenticación..." -ForegroundColor Yellow
$authInfo = & $gcloudPath auth list --filter=status:ACTIVE --format="value(account)" 2>&1
if ($LASTEXITCODE -eq 0 -and $authInfo) {
    Write-Host "   ✅ Autenticado como: $authInfo" -ForegroundColor Green
} else {
    Write-Host "   ❌ No estás autenticado" -ForegroundColor Red
    Write-Host "      Ejecuta: gcloud auth login" -ForegroundColor Yellow
}
Write-Host ""

# 2. Verificar proyecto configurado
Write-Host "2. Verificando proyecto configurado..." -ForegroundColor Yellow
$currentProject = & $gcloudPath config get-value project 2>&1
if ($currentProject -eq $PROJECT_ID) {
    Write-Host "   ✅ Proyecto correcto: $currentProject" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Proyecto actual: $currentProject" -ForegroundColor Yellow
    Write-Host "   ⚠️  Proyecto esperado: $PROJECT_ID" -ForegroundColor Yellow
    Write-Host "      Ejecuta: gcloud config set project $PROJECT_ID" -ForegroundColor Yellow
}
Write-Host ""

# 3. Verificar que el proyecto existe
Write-Host "3. Verificando existencia del proyecto..." -ForegroundColor Yellow
$projectInfo = & $gcloudPath projects describe $PROJECT_ID --format="value(projectId,name,projectNumber)" 2>&1
if ($LASTEXITCODE -eq 0) {
    $parts = $projectInfo -split "`n"
    Write-Host "   ✅ Proyecto existe:" -ForegroundColor Green
    Write-Host "      ID: $($parts[0])" -ForegroundColor Gray
    Write-Host "      Nombre: $($parts[1])" -ForegroundColor Gray
    Write-Host "      Número: $($parts[2])" -ForegroundColor Gray
    $PROJECT_NUMBER = $parts[2]
} else {
    Write-Host "   ❌ Proyecto no encontrado o sin permisos" -ForegroundColor Red
    exit 1
}
Write-Host ""

# 4. Verificar Cloud Run Service
Write-Host "4. Verificando servicio Cloud Run..." -ForegroundColor Yellow
$serviceInfo = & $gcloudPath run services describe $SERVICE --region $REGION --project $PROJECT_ID --format="yaml(status)" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ Servicio existe: $SERVICE" -ForegroundColor Green
    $serviceUrl = & $gcloudPath run services describe $SERVICE --region $REGION --project $PROJECT_ID --format="value(status.url)" 2>&1
    if ($serviceUrl) {
        Write-Host "      URL: $serviceUrl" -ForegroundColor Gray
    }
} else {
    Write-Host "   ❌ Servicio no encontrado: $SERVICE" -ForegroundColor Red
}
Write-Host ""

# 5. Obtener Service Account del servicio
Write-Host "5. Verificando Service Account del servicio..." -ForegroundColor Yellow
$serviceAccount = & $gcloudPath run services describe $SERVICE --region $REGION --project $PROJECT_ID --format="value(spec.template.spec.serviceAccountName)" 2>&1
if (-not $serviceAccount -or $serviceAccount -eq "") {
    $serviceAccount = "$PROJECT_NUMBER-compute@developer.gserviceaccount.com"
    Write-Host "   ℹ️  Usando Service Account por defecto:" -ForegroundColor Cyan
} else {
    Write-Host "   ✅ Service Account configurada:" -ForegroundColor Green
}
Write-Host "      $serviceAccount" -ForegroundColor Gray
Write-Host ""

# 6. Verificar permisos de la Service Account
Write-Host "6. Verificando permisos IAM de la Service Account..." -ForegroundColor Yellow
$iamPolicies = & $gcloudPath projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --filter="bindings.members:$serviceAccount" --format="table(bindings.role)" 2>&1
if ($iamPolicies -and $iamPolicies.Count -gt 1) {
    Write-Host "   Permisos encontrados:" -ForegroundColor Gray
    $iamPolicies | Select-Object -Skip 1 | ForEach-Object {
        if ($_ -match 'ROLE') {
            Write-Host "      ✅ $_" -ForegroundColor Green
        }
    }
} else {
    Write-Host "   ⚠️  No se encontraron permisos" -ForegroundColor Yellow
}
Write-Host ""

# 7. Verificar permisos necesarios
Write-Host "7. Verificando permisos críticos necesarios..." -ForegroundColor Yellow
$requiredRoles = @(
    "roles/secretmanager.secretAccessor",
    "roles/cloudsql.client",
    "roles/storage.objectViewer",
    "roles/artifactregistry.reader"
)

$missingRoles = @()
foreach ($role in $requiredRoles) {
    $hasRole = & $gcloudPath projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --filter="bindings.members:$serviceAccount AND bindings.role:$role" --format="value(bindings.role)" 2>&1
    if ($hasRole -eq $role) {
        Write-Host "      ✅ $role" -ForegroundColor Green
    } else {
        Write-Host "      ❌ $role (FALTANTE)" -ForegroundColor Red
        $missingRoles += $role
    }
}
Write-Host ""

# 8. Verificar Secrets en Secret Manager
Write-Host "8. Verificando Secrets en Secret Manager..." -ForegroundColor Yellow
$secrets = @("jwt-secret-key", "db-password")
foreach ($secretName in $secrets) {
    $secretInfo = & $gcloudPath secrets describe $secretName --project=$PROJECT_ID --format="value(name)" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      ✅ $secretName existe" -ForegroundColor Green
        
        # Verificar permisos del secret
        $secretPolicy = & $gcloudPath secrets get-iam-policy $secretName --project=$PROJECT_ID --format="value(bindings.members)" 2>&1 | Select-String $serviceAccount
        if ($secretPolicy) {
            Write-Host "         ✅ Service Account tiene acceso" -ForegroundColor Green
        } else {
            Write-Host "         ❌ Service Account NO tiene acceso" -ForegroundColor Red
        }
    } else {
        Write-Host "      ❌ $secretName NO existe" -ForegroundColor Red
    }
}
Write-Host ""

# 9. Verificar Cloud SQL Instance
Write-Host "9. Verificando instancia Cloud SQL..." -ForegroundColor Yellow
$sqlInstance = "$PROJECT_ID:$REGION:residencias"
$sqlInfo = & $gcloudPath sql instances describe residencias --project=$PROJECT_ID --format="value(name,state,databaseVersion)" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "      ✅ Instancia existe: residencias" -ForegroundColor Green
    $parts = $sqlInfo -split "`n"
    if ($parts.Count -ge 2) {
        Write-Host "         Estado: $($parts[1])" -ForegroundColor Gray
        Write-Host "         Versión: $($parts[2])" -ForegroundColor Gray
    }
} else {
    Write-Host "      ❌ Instancia no encontrada" -ForegroundColor Red
}
Write-Host ""

# 10. Verificar variables de entorno del servicio
Write-Host "10. Verificando variables de entorno del servicio..." -ForegroundColor Yellow
$envVars = & $gcloudPath run services describe $SERVICE --region $REGION --project $PROJECT_ID --format="get(spec.template.spec.containers[0].env)" 2>&1
if ($envVars) {
    Write-Host "      Variables configuradas:" -ForegroundColor Gray
    $envVars | Select-String -Pattern "name:|value:" | ForEach-Object {
        if ($_ -match "name:\s*(\w+)") {
            $varName = $matches[1]
            Write-Host "         ✅ $varName" -ForegroundColor Green
        }
    }
} else {
    Write-Host "      ⚠️  No se encontraron variables de entorno" -ForegroundColor Yellow
}
Write-Host ""

# 11. Verificar última revisión
Write-Host "11. Verificando última revisión..." -ForegroundColor Yellow
$lastRevision = & $gcloudPath run revisions list --service $SERVICE --region $REGION --project $PROJECT_ID --limit 1 --format="value(name,status.conditions[0].status)" 2>&1
if ($lastRevision) {
    $parts = $lastRevision -split "`t"
    Write-Host "      Revisión: $($parts[0])" -ForegroundColor Gray
    if ($parts[1] -eq "True") {
        Write-Host "      ✅ Estado: Ready" -ForegroundColor Green
    } else {
        Write-Host "      ⚠️  Estado: $($parts[1])" -ForegroundColor Yellow
    }
} else {
    Write-Host "      ⚠️  No se encontraron revisiones" -ForegroundColor Yellow
}
Write-Host ""

# Resumen
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RESUMEN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($missingRoles.Count -gt 0) {
    Write-Host "⚠️  ACCIONES NECESARIAS:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Permisos faltantes para $serviceAccount:" -ForegroundColor Yellow
    foreach ($role in $missingRoles) {
        Write-Host "   gcloud projects add-iam-policy-binding $PROJECT_ID \`" -ForegroundColor Gray
        Write-Host "       --member='serviceAccount:$serviceAccount' \`" -ForegroundColor Gray
        Write-Host "       --role='$role'" -ForegroundColor Gray
        Write-Host ""
    }
    Write-Host "O ejecuta: .\otorgar_permisos_cloud_run.ps1" -ForegroundColor Cyan
} else {
    Write-Host "✅ Configuración básica correcta" -ForegroundColor Green
}

Write-Host ""
Write-Host "Para más detalles:" -ForegroundColor Cyan
Write-Host "   - Ver logs: gcloud run services logs read $SERVICE --region $REGION --project $PROJECT_ID" -ForegroundColor Gray
Write-Host "   - Ver servicio: https://console.cloud.google.com/run/detail/$REGION/$SERVICE?project=$PROJECT_ID" -ForegroundColor Gray
Write-Host ""
