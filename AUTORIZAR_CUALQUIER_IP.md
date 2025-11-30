# 🌐 Autorizar Cualquier IP en Cloud SQL

## ⚠️ ADVERTENCIA DE SEGURIDAD

Autorizar `0.0.0.0/0` permite conexiones desde **cualquier IP en Internet**. Esto es:
- ✅ **Útil para desarrollo** y pruebas
- ❌ **NO recomendado para producción** (riesgo de seguridad)

## 📋 Pasos para Autorizar Cualquier IP

### 1. Acceder a Cloud SQL Console

Ve a: https://console.cloud.google.com/sql/instances/residencias/overview

### 2. Ir a la Sección de Conexiones

**Opción A: Desde el menú lateral**
- Haz clic en **"Conexiones"** o **"Connections"** en el menú izquierdo

**Opción B: Desde el botón Editar**
- Haz clic en **"Editar"** (botón en la parte superior)
- Busca la pestaña **"Conexiones"** o **"Connections"**

### 3. Agregar Red Autorizada

1. Busca la sección **"Redes autorizadas"** o **"Authorized networks"**
2. Haz clic en **"Agregar red"** o **"Add network"**
3. En el campo **"Red"** o **"Network"**, ingresa:
   ```
   0.0.0.0/0
   ```
4. (Opcional) Agrega un nombre descriptivo: `Cualquier IP - Desarrollo`
5. Haz clic en **"Agregar"** o **"Add"**

### 4. Guardar Cambios

- Si estás en modo edición, haz clic en **"Guardar"** o **"Save"** en la parte inferior
- Espera a que se complete la operación (puede tardar 1-2 minutos)

### 5. Verificar

Después de guardar, deberías ver `0.0.0.0/0` en la lista de redes autorizadas.

## ✅ Verificación

Una vez autorizado, prueba la conexión:

```powershell
python test_conexion_bd.py
```

O inicia el servidor:

```powershell
.\start_server.ps1
```

## 🔒 Alternativa Más Segura

Si solo quieres autorizar tu IP actual sin tener que cambiarla cada vez, usa **Cloud SQL Proxy**:

```powershell
.\setup_cloud_sql_proxy.ps1
.\configurar_proxy_env.ps1
.\start_server_with_proxy.ps1
```

Esto es más seguro y no requiere autorizar IPs.

## 📝 Notas

- Los cambios pueden tardar 1-2 minutos en aplicarse
- `0.0.0.0/0` permite conexiones desde cualquier ubicación
- Para producción, considera usar Cloud SQL Proxy o autorizar IPs específicas

