@echo off
REM Script para reiniciar el servidor Flask
REM Uso: restart_server.bat

echo ========================================
echo   Reiniciando Servidor Flask Violetas
echo ========================================
echo.

REM Detener procesos de Python que estén ejecutando app.py
echo Deteniendo procesos existentes...

REM Buscar y detener procesos que tienen app.py en la línea de comandos
for /f "tokens=2 delims=," %%a in ('wmic process where "name='python.exe' or name='pythonw.exe'" get ProcessId^,CommandLine /format:csv ^| findstr /I "app.py"') do (
    if not "%%a"=="ProcessId" (
        echo   Deteniendo proceso PID: %%a
        taskkill /PID %%a /F >nul 2>&1
    )
)

timeout /t 2 /nobreak >nul

REM Verificar que el archivo app.py existe
if not exist "app.py" (
    echo ERROR: No se encontró app.py en el directorio actual.
    echo Asegúrate de ejecutar este script desde el directorio del proyecto.
    pause
    exit /b 1
)

REM Verificar que existe el archivo .env
if not exist ".env" (
    echo ADVERTENCIA: No se encontró el archivo .env
    echo El servidor puede fallar si faltan variables de entorno.
    echo.
)

REM Iniciar el servidor
echo Iniciando servidor Flask...
echo   URL: http://localhost:5000
echo   Presiona Ctrl+C para detener el servidor
echo.
echo ========================================
echo.

REM Ejecutar en la misma terminal para ver logs
python app.py
