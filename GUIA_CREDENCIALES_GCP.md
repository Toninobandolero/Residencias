# Guía Paso a Paso para Obtener Credenciales desde GCP

## Paso 1: Acceder a Cloud SQL

1. Ve a: https://console.cloud.google.com/sql
2. Inicia sesión con tu cuenta de Google Cloud
3. Selecciona tu proyecto (479706)

## Paso 2: Ver el Nombre de la Base de Datos

1. Haz clic en tu instancia: **residencias**
2. En el menú lateral izquierdo, haz clic en **"Bases de datos"**
3. Verás una lista de bases de datos. El nombre más común es:
   - `postgres` (por defecto)
   - O el nombre que hayas creado (ej: `residencias`, `violetas`)

**Anota el nombre de la base de datos:** ________________

## Paso 3: Ver el Usuario

1. En el mismo panel, haz clic en **"Usuarios"** en el menú lateral
2. Verás una lista de usuarios. Los más comunes son:
   - `postgres` (usuario por defecto)
   - O un usuario personalizado que hayas creado

**Anota el nombre del usuario:** ________________

## Paso 4: Obtener o Restablecer la Contraseña

### Si recuerdas la contraseña:
- Úsala directamente

### Si NO recuerdas la contraseña:

1. En la pestaña **"Usuarios"**
2. Haz clic en los **3 puntos (⋮)** junto al usuario
3. Selecciona **"Cambiar contraseña"**
4. Ingresa una nueva contraseña
5. Haz clic en **"Aceptar"**

**⚠️ IMPORTANTE:** Anota esta contraseña en un lugar seguro.

**Anota la contraseña:** ________________

## Paso 5: Verificar Autorización de IP

Para que puedas conectarte desde tu máquina local:

1. En la instancia, ve a **"Conexiones"** → **"Autorizar redes"**
2. Asegúrate de que tu IP esté autorizada, o agrega:
   - **0.0.0.0/0** (para permitir todas las IPs - solo para desarrollo)
   - O tu IP específica (más seguro)

## Paso 6: Usar el Script de Configuración

Una vez que tengas los datos, ejecuta:

```bash
python find_db_credentials.py
```

Este script te guiará paso a paso y probará la conexión.

## Resumen de Datos Necesarios

- ✅ **DB_HOST**: 34.155.185.9 (ya configurado)
- ✅ **DB_PORT**: 5432 (ya configurado)
- ❓ **DB_NAME**: ________________ (obtener del Paso 2)
- ❓ **DB_USER**: ________________ (obtener del Paso 3)
- ❓ **DB_PASSWORD**: ________________ (obtener del Paso 4)

