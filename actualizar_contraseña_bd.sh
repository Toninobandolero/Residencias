#!/bin/bash
# Script para actualizar contraseña de Cloud SQL y el secret

# CONTRASEÑA - Reemplaza con la que quieras usar
# Opción 1: gPtnfcS17JaoOWoDLAJKl8Bz4LVZBqJSIB7Mj/GFYjg=
# Opción 2: 089zRwEG0VLqO2eZLc3dYZOpy3pfA3sleijPJONSJIU=
NUEVA_PASSWORD="089zRwEG0VLqO2eZLc3dYZOpy3pfA3sleijPJONSJIU="

echo "=========================================="
echo "  ACTUALIZANDO CONTRASEÑA DE BD"
echo "=========================================="
echo ""
echo "⚠️  Usando contraseña: ${NUEVA_PASSWORD:0:10}..."
echo ""

# Paso 1: Cambiar contraseña en Cloud SQL
echo "1. Cambiando contraseña en Cloud SQL..."
gcloud sql users set-password postgres \
  --instance=residencias \
  --password="$NUEVA_PASSWORD" \
  --project=residencias-479706

if [ $? -eq 0 ]; then
    echo "   ✅ Contraseña actualizada en Cloud SQL"
else
    echo "   ❌ Error al actualizar contraseña en Cloud SQL"
    exit 1
fi

echo ""

# Paso 2: Actualizar el secret
echo "2. Actualizando secret db-password..."
echo -n "$NUEVA_PASSWORD" | gcloud secrets versions add db-password \
  --data-file=- \
  --project=residencias-479706

if [ $? -eq 0 ]; then
    echo "   ✅ Secret actualizado"
else
    echo "   ❌ Error al actualizar secret"
    exit 1
fi

echo ""
echo "=========================================="
echo "  ✅ ACTUALIZACIÓN COMPLETA"
echo "=========================================="
echo ""
echo "Espera 1-2 minutos y prueba el login en:"
echo "https://violetas-app-621063984498.europe-west9.run.app"
echo ""
