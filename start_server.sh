#!/bin/bash
# Script para iniciar el servidor Flask en macOS/Linux
# Uso: ./start_server.sh

echo "========================================"
echo "  Iniciando Servidor Flask Violetas"
echo "========================================"
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

echo "Iniciando servidor Flask..."
echo "  URL: http://localhost:5001"
echo "  (Puerto 5001 para evitar conflicto con AirPlay en macOS)"
echo "  Presiona Ctrl+C para detener el servidor"
echo ""
echo "========================================"
echo ""

# Iniciar el servidor
python3 app.py

