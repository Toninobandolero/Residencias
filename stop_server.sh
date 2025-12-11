#!/bin/bash
# Script para detener el servidor Flask en macOS/Linux
# Uso: ./stop_server.sh

echo "Deteniendo servidor Flask..."

# Buscar procesos de Python que ejecutan app.py
PROCESSES=$(ps aux | grep "[p]ython.*app.py" | awk '{print $2}')

if [ -n "$PROCESSES" ]; then
    echo "$PROCESSES" | while read pid; do
        if [ -n "$pid" ]; then
            echo "  Deteniendo proceso PID: $pid"
            kill -9 "$pid" 2>/dev/null
        fi
    done
    sleep 1
    echo "✅ Servidor detenido"
else
    echo "  No hay procesos de Python ejecutando app.py"
fi

# También verificar por puerto
PORT_PROCESS=$(lsof -ti:5001 2>/dev/null)
if [ -n "$PORT_PROCESS" ]; then
    echo "  Liberando puerto 5001..."
    kill -9 $PORT_PROCESS 2>/dev/null
    sleep 1
fi

# Verificar si hay archivos PID
if [ -f "server.pid" ]; then
    OLD_PID=$(cat server.pid)
    if [ -n "$OLD_PID" ] && ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "  Deteniendo proceso del PID file: $OLD_PID"
        kill -9 "$OLD_PID" 2>/dev/null
    fi
    rm -f server.pid
fi

echo "✅ Proceso completado"
