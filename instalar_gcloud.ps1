# Script para instalar Google Cloud SDK en Windows
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  INSTALACION DE GOOGLE CLOUD SDK" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Opciones de instalacion:" -ForegroundColor Yellow
Write-Host "1. Descargar instalador automaticamente (recomendado)" -ForegroundColor Green
Write-Host "2. Abrir pagina de descarga manual" -ForegroundColor Green
Write-Host "3. Instalar usando winget (si esta disponible)" -ForegroundColor Green
Write-Host ""

$opcion = Read-Host "Selecciona una opcion (1-3)"

if ($opcion -eq "1") {
    Write-Host ""
    Write-Host "Descargando instalador de Google Cloud SDK..." -ForegroundColor Yellow
    
    $url = "https://dl.google.com/dl/cloudsdk/channels/rapid/GoogleCloudSDKInstaller.exe"
    $output = "$env:TEMP\GoogleCloudSDKInstaller.exe"
    
    try {
        Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing
        Write-Host "Instalador descargado en: $output" -ForegroundColor Green
        Write-Host ""
        Write-Host "Ejecutando instalador..." -ForegroundColor Yellow
        Write-Host "Sigue las instrucciones en la ventana que se abrira." -ForegroundColor Cyan
        Write-Host ""
        
        Start-Process -FilePath $output -Wait
        
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  INSTALACION COMPLETADA" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "IMPORTANTE: Reinicia PowerShell y luego ejecuta:" -ForegroundColor Yellow
        Write-Host "  gcloud init" -ForegroundColor Cyan
        Write-Host ""
        
    } catch {
        Write-Host "Error al descargar el instalador: $_" -ForegroundColor Red
        Write-Host "Intenta la opcion 2 para descarga manual" -ForegroundColor Yellow
    }
    
} elseif ($opcion -eq "2") {
    Write-Host ""
    Write-Host "Abriendo pagina de descarga..." -ForegroundColor Yellow
    Start-Process "https://cloud.google.com/sdk/docs/install"
    Write-Host ""
    Write-Host "Descarga e instala el instalador desde la pagina web." -ForegroundColor Cyan
    Write-Host "Despues de instalar, reinicia PowerShell y ejecuta: gcloud init" -ForegroundColor Yellow
    
} elseif ($opcion -eq "3") {
    Write-Host ""
    Write-Host "Intentando instalar con winget..." -ForegroundColor Yellow
    
    try {
        winget install Google.CloudSDK
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  INSTALACION COMPLETADA" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "IMPORTANTE: Reinicia PowerShell y luego ejecuta:" -ForegroundColor Yellow
        Write-Host "  gcloud init" -ForegroundColor Cyan
        Write-Host ""
    } catch {
        Write-Host "Error: winget no esta disponible o fallo la instalacion" -ForegroundColor Red
        Write-Host "Intenta la opcion 1 o 2" -ForegroundColor Yellow
    }
    
} else {
    Write-Host "Opcion invalida" -ForegroundColor Red
}

