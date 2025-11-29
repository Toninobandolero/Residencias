# Cómo Autorizar tu IP en Cloud SQL

## Paso a Paso

1. **Ve a la consola de Cloud SQL:**
   - https://console.cloud.google.com/sql/instances/residencias/overview

2. **En el menú lateral izquierdo, busca:**
   - **"Conexiones"** o **"Connections"**
   - O busca **"Autorizar redes"** o **"Authorized networks"**

3. **Si ves "Autorizar redes" o "Authorized networks":**
   - Haz clic en **"Agregar red"** o **"Add network"**
   - Para desarrollo rápido, agrega: `0.0.0.0/0`
     - ⚠️ Esto permite conexiones desde cualquier IP (solo para desarrollo)
   - O agrega tu IP específica (más seguro)
   - Haz clic en **"Agregar"** o **"Add"**

4. **Si NO ves la opción "Autorizar redes":**
   - Puede que esté en otra sección
   - Busca en: **"Configuración"** → **"Redes"**
   - O en: **"Editar"** (botón en la parte superior) → pestaña **"Conexiones"**

## Obtener tu IP Pública

Para agregar solo tu IP (más seguro):

1. Abre: https://whatismyipaddress.com/
2. Copia tu **IPv4 Address**
3. Agrégala en Cloud SQL con formato: `TU_IP/32`
   - Ejemplo: Si tu IP es `123.45.67.89`, agrega: `123.45.67.89/32`

## Alternativa: Usar Cloud SQL Proxy

Si no puedes autorizar IPs, puedes usar Cloud SQL Proxy:
- Más seguro
- No requiere autorizar IPs
- Requiere instalar el proxy localmente

¿Quieres que te ayude a configurar Cloud SQL Proxy?

