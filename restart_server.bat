@echo off
REM Script para reiniciar el servidor Flask (versión batch)
REM Uso: restart_server.bat

echo ========================================
echo   Reiniciando Servidor Flask Violetas
echo ========================================
echo.

echo Deteniendo procesos existentes...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *app.py*" 2>nul
if %errorlevel% equ 0 (
    echo   Procesos detenidos.
) else (
    echo   No hay procesos de Python ejecutandose.
)
echo.

if not exist app.py (
    echo ERROR: No se encontro app.py en el directorio actual.
    echo Asegurate de ejecutar este script desde el directorio del proyecto.
    pause
    exit /b 1
)

echo Iniciando servidor Flask...
echo   URL: http://localhost:5000
echo   Presiona Ctrl+C para detener el servidor
echo.
echo ========================================
echo.

start "Servidor Flask Violetas" cmd /k "python app.py"

echo Servidor iniciado en una nueva ventana.
echo Puedes cerrar esta ventana.
pause

