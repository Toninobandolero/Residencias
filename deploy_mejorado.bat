@echo off
REM Script de despliegue alternativo usando .bat (no requiere cambiar políticas)
REM Este script llama directamente a gcloud sin usar PowerShell

echo ========================================
echo   DESPLIEGUE A CLOUD RUN
echo ========================================
echo.

REM Verificar que gcloud está disponible
where gcloud >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Google Cloud SDK no encontrado
    echo Instala desde: https://cloud.google.com/sdk/docs/install
    pause
    exit /b 1
)

echo Desplegando a Cloud Run...
echo Esto puede tardar varios minutos...
echo.

gcloud run deploy violetas-app ^
    --source . ^
    --region europe-west9 ^
    --platform managed ^
    --allow-unauthenticated ^
    --add-cloudsql-instances residencias-479706:europe-west9:residencias ^
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias,GCS_BUCKET_NAME=violetas-documentos" ^
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" ^
    --memory 2Gi ^
    --cpu 2 ^
    --timeout 300 ^
    --max-instances 10 ^
    --min-instances 0 ^
    --project=residencias-479706

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo   DESPLIEGUE EXITOSO
    echo ========================================
    echo.
    gcloud run services describe violetas-app --region europe-west9 --format="value(status.url)" --project=residencias-479706
    echo.
    echo Para ver logs:
    echo   gcloud run services logs read violetas-app --region europe-west9 --project residencias-479706
) else (
    echo.
    echo ========================================
    echo   ERROR EN EL DESPLIEGUE
    echo ========================================
    echo.
    echo Revisa los logs arriba para mas detalles.
    echo https://console.cloud.google.com/run?project=residencias-479706
)

pause

