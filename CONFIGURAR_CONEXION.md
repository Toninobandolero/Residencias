# Cómo Configurar la Conexión a Cloud SQL

## Opción 1: Autorizar tu IP (Más Simple)

### Ubicación exacta en GCP Console:

1. Ve a: https://console.cloud.google.com/sql/instances
2. Haz clic en tu instancia: **residencias**
3. En la parte superior, verás varias pestañas. Busca y haz clic en:
   - **"Conexiones"** o **"Connections"** (puede estar en el menú de 3 líneas ☰ si está oculto)
4. Dentro de "Conexiones", busca la sección:
   - **"Redes autorizadas"** o **"Authorized networks"**
5. Haz clic en **"Agregar red"** o **"Add network"**
6. En "Red":
   - Para desarrollo: escribe `0.0.0.0/0`
   - O deja el campo en blanco y haz clic en "Agregar"
7. Haz clic en **"Guardar"** o **"Save"**

### Si no encuentras "Conexiones":

1. En la página de tu instancia, busca el botón **"Editar"** o **"Edit"** (arriba a la derecha)
2. Se abrirá un formulario. Busca la pestaña o sección:
   - **"Conexiones"** o **"Connections"**
   - O **"Redes"** o **"Networks"**
3. Ahí deberías ver **"Redes autorizadas"**

---

## Opción 2: Usar Cloud SQL Proxy (Recomendado - Más Seguro)

Cloud SQL Proxy no requiere autorizar IPs y es más seguro.

### Pasos:

1. **Descargar Cloud SQL Proxy:**
   - Ve a: https://cloud.google.com/sql/docs/postgres/sql-proxy
   - O descarga directo: https://dl.google.com/cloudsql/cloud_sql_proxy_x64.exe
   - Guárdalo en una carpeta (ej: `C:\cloud-sql-proxy\`)

2. **Obtener la cadena de conexión:**
   - Ya la tienes: `residencias-479706:europe-west9:residencias`

3. **Ejecutar el proxy:**
   ```bash
   cloud_sql_proxy_x64.exe -instances=residencias-479706:europe-west9:residencias=tcp:5432
   ```

4. **Actualizar .env:**
   - Cambiar `DB_HOST=127.0.0.1` (localhost, porque el proxy redirige)

¿Quieres que te ayude a configurar Cloud SQL Proxy? Es más fácil y seguro.

