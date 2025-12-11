#!/bin/bash
# Script para iniciar el servidor Flask con Cloud SQL Proxy en macOS/Linux
# Uso: ./start_server_with_proxy.sh

echo "========================================"
echo "  INICIANDO SERVIDOR CON CLOUD SQL PROXY"
echo "========================================"
echo ""

# Verificar que existe app.py
if [ ! -f "app.py" ]; then
    echo "ERROR: No se encontró app.py"
    exit 1
fi

# Verificar .env
if [ ! -f ".env" ]; then
    echo "ADVERTENCIA: No se encontró .env"
fi

# Directorio del proxy
PROXY_DIR="./cloud-sql-proxy"
PROXY_EXE="$PROXY_DIR/cloud_sql_proxy"

# Verificar si el proxy está instalado
if [ ! -f "$PROXY_EXE" ]; then
    echo "⚠️  Cloud SQL Proxy no está instalado"
    echo "   Ejecuta: ./setup_cloud_sql_proxy.ps1"
    exit 1
fi

# Cargar variables de entorno desde .env
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Obtener cadena de conexión
if [ -z "$CLOUD_SQL_CONNECTION_NAME" ]; then
    CLOUD_SQL_CONNECTION_NAME="residencias-479706:europe-west9:residencias"
    echo "⚠️  CLOUD_SQL_CONNECTION_NAME no definido"
    echo "   Usando: $CLOUD_SQL_CONNECTION_NAME"
fi

# Configurar para usar proxy
export DB_USE_PROXY="true"

echo ""
echo "🚀 Iniciando Cloud SQL Proxy..."
echo "   Instancia: $CLOUD_SQL_CONNECTION_NAME"
echo "   Puerto: 5432"
echo ""

# Iniciar proxy en segundo plano
$PROXY_EXE --port=5432 --address=127.0.0.1 $CLOUD_SQL_CONNECTION_NAME > /tmp/cloud_sql_proxy.log 2>&1 &
PROXY_PID=$!

# Esperar un momento para que el proxy inicie
sleep 3

# Verificar que el proxy está corriendo
if ps -p $PROXY_PID > /dev/null 2>&1; then
    echo "✅ Cloud SQL Proxy iniciado (PID: $PROXY_PID)"
else
    echo "❌ El proxy se detuvo inmediatamente"
    echo "   Revisa los logs: cat /tmp/cloud_sql_proxy.log"
    exit 1
fi

# Función para limpiar al salir
cleanup() {
    echo ""
    echo "🛑 Deteniendo servicios..."
    if ps -p $PROXY_PID > /dev/null 2>&1; then
        kill $PROXY_PID 2>/dev/null
        echo "   ✅ Cloud SQL Proxy detenido"
    fi
}

trap cleanup EXIT INT TERM

echo ""
echo "🚀 Iniciando servidor Flask..."
echo "   URL: http://localhost:5001"
echo "   Presiona Ctrl+C para detener ambos servicios"
echo ""
echo "========================================"
echo ""

# Iniciar servidor Flask (logs visibles)
python3 app.py
