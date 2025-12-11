#!/bin/bash
# Script para reiniciar el servidor Flask en macOS/Linux
# Uso: ./restart_server.sh

echo "========================================"
echo "  Reiniciando Servidor Flask Violetas"
echo "========================================"
echo ""

# Detener servidor anterior
if [ -f "./stop_server.sh" ]; then
    ./stop_server.sh
else
    echo "Deteniendo procesos existentes..."
    pkill -f "python.*app.py" 2>/dev/null
    lsof -ti:5001 | xargs kill -9 2>/dev/null
    sleep 2
    echo "✅ Procesos detenidos"
fi

echo ""

# Verificar que el archivo app.py existe
if [ ! -f "app.py" ]; then
    echo "ERROR: No se encontró app.py en el directorio actual."
    echo "Asegúrate de ejecutar este script desde el directorio del proyecto."
    exit 1
fi

# Verificar que existe el archivo .env
if [ ! -f ".env" ]; then
    echo "ADVERTENCIA: No se encontró el archivo .env"
    echo "El servidor puede fallar si faltan variables de entorno."
    echo ""
fi

# Iniciar el servidor
echo "Iniciando servidor Flask..."
echo "  URL: http://localhost:5001"
echo "  (Puerto 5001 - configurable con variable PORT)"
echo "  Presiona Ctrl+C para detener el servidor"
echo ""
echo "========================================"
echo ""

# Iniciar el servidor (logs visibles en terminal)
python3 app.py
