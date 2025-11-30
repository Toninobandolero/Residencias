# 🔧 Guía Técnica - Sistema Violetas

## 📋 Tabla de Contenidos

1. [Arquitectura del Sistema](#arquitectura-del-sistema)
2. [Configuración de Cloud SQL Proxy](#configuración-de-cloud-sql-proxy)
3. [Configuración de Base de Datos](#configuración-de-base-de-datos)
4. [Solución de Problemas](#solución-de-problemas)
5. [Desarrollo y Testing](#desarrollo-y-testing)

---

## 🏗️ Arquitectura del Sistema

### Componentes Principales

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  Frontend   │         │   Backend    │         │  Cloud SQL  │
│  (SPA)      │────────▶│   (Flask)    │────────▶│  (PostgreSQL)│
│ index.html  │         │   app.py     │         │   GCP       │
└─────────────┘         └──────────────┘         └─────────────┘
     :5000                   :5000                      :5432
```

### Flujo de Autenticación

```
1. Usuario → Frontend → POST /api/v1/login
2. Backend verifica credenciales en BD
3. Backend genera token JWT
4. Frontend guarda token en localStorage
5. Todas las peticiones incluyen: Authorization: Bearer <token>
6. Backend valida token y filtra por id_residencia
```

### Middleware de Autenticación

El sistema usa `@app.before_request` para validar tokens JWT:

- **Rutas públicas**: `/`, `/api/v1/login`, `/health`
- **Rutas protegidas**: Todas las demás requieren token válido
- **Filtrado automático**: Todas las consultas incluyen `WHERE id_residencia = g.id_residencia`

---

## 🔧 Configuración de Cloud SQL Proxy

### ¿Por Qué Cloud SQL Proxy?

**Problema sin proxy:**
- ❌ Necesitas autorizar tu IP cada vez que cambias de ubicación
- ❌ El sistema deja de funcionar cuando tu IP cambia
- ❌ Molesto y poco práctico

**Solución con proxy:**
- ✅ No necesitas autorizar IPs nunca más
- ✅ Funciona desde cualquier ubicación
- ✅ Más seguro (conexión encriptada)
- ✅ Recomendado por Google Cloud

### Instalación Automática

```powershell
# 1. Configurar Cloud SQL Proxy
.\setup_cloud_sql_proxy.ps1

# 2. Configurar .env
.\configurar_proxy_env.ps1

# 3. Iniciar servidor (inicia proxy y Flask juntos)
.\start_server_with_proxy.ps1
```

### Configuración Manual

1. **Descargar Cloud SQL Proxy:**
   - URL: https://github.com/GoogleCloudPlatform/cloud-sql-proxy/releases
   - Archivo: `cloud-sql-proxy.x64.exe` (Windows)
   - Guardar en: `cloud-sql-proxy/cloud_sql_proxy.exe`

2. **Configurar .env:**
   ```env
   DB_USE_PROXY=true
   DB_HOST=127.0.0.1
   DB_PORT=5432
   CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias
   GOOGLE_APPLICATION_CREDENTIALS=residencias-479706-8c3bdbf8bbf8.json
   ```

3. **Iniciar proxy:**
   ```powershell
   .\cloud-sql-proxy\cloud_sql_proxy.exe --port=5432 --address=127.0.0.1 residencias-479706:europe-west9:residencias
   ```

### Requisitos

1. **Archivo de credenciales JSON de GCP:**
   - Obtener en: https://console.cloud.google.com/apis/credentials
   - Crear cuenta de servicio o usar existente
   - Descargar clave JSON
   - Guardar en directorio del proyecto

2. **Cadena de conexión:**
   - Formato: `PROYECTO:REGION:INSTANCIA`
   - Ejemplo: `residencias-479706:europe-west9:residencias`

### Verificación

```powershell
# Verificar que el proxy está corriendo
Get-Process | Where-Object {$_.ProcessName -like "*cloud_sql*"}

# Probar conexión
python test_conexion_bd.py
```

---

## 🗄️ Configuración de Base de Datos

### Variables de Entorno

```env
# Conexión
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=tu-contraseña
DB_PORT=5432

# Con Proxy (Recomendado)
DB_USE_PROXY=true
DB_HOST=127.0.0.1
CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias
GOOGLE_APPLICATION_CREDENTIALS=residencias-479706-8c3bdbf8bbf8.json

# Sin Proxy (Requiere IP autorizada)
# DB_USE_PROXY=false
# DB_HOST=34.155.185.9
```

### Crear Esquema de Base de Datos

```powershell
python create_database.py
```

O ejecutar SQL directamente:

```powershell
psql -h DB_HOST -U DB_USER -d DB_NAME -f create_schema.sql
```

### Estructura de Tablas

**Tablas principales:**
- `residencia` - Residencias (Violetas 1 y Violetas 2)
- `rol` - Roles de usuario (Administrador, Director, Personal)
- `usuario` - Usuarios del sistema
- `residente` - Residentes
- `pago_residente` - Pagos de residentes
- `proveedor` - Proveedores
- `pago_proveedor` - Pagos a proveedores
- `personal` - Personal de la residencia
- `documento_residente` - Documentos adjuntos

### Crear Usuario Inicial

```python
from db_utils import create_user

create_user(
    email="admin@violetas1.com",
    password="admin123",
    id_rol=1,  # Administrador
    id_residencia=1  # Violetas 1
)
```

---

## 🆘 Solución de Problemas

### Error: "Connection timed out"

**Causa**: IP no autorizada en Cloud SQL

**Solución 1: Usar Cloud SQL Proxy (Recomendado)**
```powershell
.\setup_cloud_sql_proxy.ps1
.\configurar_proxy_env.ps1
.\start_server_with_proxy.ps1
```

**Solución 2: Autorizar IP**
1. Obtener IP: `python obtener_mi_ip.py`
2. Autorizar en: https://console.cloud.google.com/sql/instances/residencias/overview
3. Agregar red: `TU_IP/32`
4. Esperar 1-2 minutos

### Error: "Token de autenticación requerido"

**Causa**: Token JWT inválido o expirado

**Solución:**
1. Cerrar sesión y volver a iniciar sesión
2. Verificar token en localStorage (F12 → Console):
   ```javascript
   console.log(localStorage.getItem('violetas_token'));
   ```

### No se listan los residentes

**Diagnóstico:**

1. **Verificar conexión a BD:**
   ```powershell
   python test_conexion_bd.py
   ```

2. **Verificar que hay residentes:**
   ```python
   from db_connector import get_db_connection
   conn = get_db_connection()
   cursor = conn.cursor()
   cursor.execute("SELECT COUNT(*) FROM residente WHERE id_residencia = 1")
   print(cursor.fetchone()[0])
   ```

3. **Verificar token y petición:**
   - Abrir consola del navegador (F12)
   - Verificar que el token existe
   - Probar petición manualmente

**Posibles causas:**
- No hay residentes en la BD para tu `id_residencia`
- Token inválido o expirado
- Error de conexión a la base de datos
- El usuario tiene `id_residencia` diferente a los residentes

### El proxy no inicia

**Error: "Failed to get instance"**
- Verificar que `CLOUD_SQL_CONNECTION_NAME` sea correcto
- Formato: `PROYECTO:REGION:INSTANCIA`

**Error: "Failed to get credentials"**
- Verificar que `GOOGLE_APPLICATION_CREDENTIALS` apunte al archivo JSON
- Verificar que el archivo JSON existe y es válido

### Puerto 5432 ya en uso

**Solución:**
1. Cambiar puerto del proxy en `start_server_with_proxy.ps1`:
   ```powershell
   --port=5433  # En lugar de 5432
   ```

2. Actualizar `.env`:
   ```env
   DB_PORT=5433
   ```

### Scripts de Diagnóstico

```powershell
# Diagnóstico completo
python diagnostico_sistema.py

# Probar conexión a BD
python test_conexion_bd.py

# Probar API de residentes
python test_residentes_api.py

# Obtener IP actual
python obtener_mi_ip.py
```

---

## 🧪 Desarrollo y Testing

### Estructura de Código

```
app.py                 # Aplicación Flask principal
db_connector.py        # Conexión a PostgreSQL (soporta proxy)
validators.py          # Validación de entrada
storage_manager.py     # Gestión de documentos en Cloud Storage
static/index.html      # Frontend SPA
```

### Validación de Datos

El sistema usa `validators.py` para validar:
- Textos (longitud, formato)
- Números (rangos, tipos)
- Fechas (formato, validez)
- Emails (formato)
- Teléfonos (formato)
- Montos (positivos, decimales)

### Testing

```powershell
# Ejecutar tests
pytest tests/

# Test específico
pytest tests/test_endpoints.py
```

### Logs y Debugging

**Backend (Flask):**
- Modo debug activado por defecto
- Logs en consola
- Errores detallados en desarrollo

**Frontend:**
- Consola del navegador (F12)
- Verificar peticiones en Network tab
- Verificar localStorage en Application tab

### Backup de Base de Datos

```powershell
# Backup automático
.\backup.ps1

# O manualmente
python backup_database.py
```

Los backups se guardan en `backups/` con formato:
```
backup_YYYYMMDD_HHMMSS.sql
```

---

## 🔐 Seguridad

### Filtrado por Residencia

**IMPERATIVO**: Todas las consultas filtran por `id_residencia`:

```python
# Ejemplo en endpoint
cursor.execute("""
    SELECT * FROM residente 
    WHERE id_residencia = %s
""", (g.id_residencia,))
```

### Validación de Entrada

Todos los endpoints validan entrada usando `validators.py`:
- Prevención de SQL injection
- Validación de tipos
- Validación de rangos
- Sanitización de datos

### Tokens JWT

- Expiración: 24 horas
- Algoritmo: HS256
- Payload: `id_usuario`, `id_rol`, `id_residencia`, `exp`

---

## 📊 Monitoreo

### Health Check

```bash
GET http://localhost:5000/health
```

Respuesta:
```json
{
  "service": "Violetas Backend API",
  "status": "ok",
  "timestamp": "2025-11-29T13:08:41.394208"
}
```

### Verificar Estado del Sistema

```powershell
# Verificar procesos
Get-Process python
Get-Process | Where-Object {$_.ProcessName -like "*cloud_sql*"}

# Verificar puertos
netstat -ano | Select-String -Pattern ":5000"
netstat -ano | Select-String -Pattern ":5432"
```

---

## 🚀 Despliegue

### Variables de Entorno en Producción

```env
# Desactivar debug
FLASK_ENV=production
FLASK_DEBUG=False

# Configuración de BD (usar proxy en producción también)
DB_USE_PROXY=true
DB_HOST=127.0.0.1
```

### Consideraciones

- Usar Cloud SQL Proxy también en producción
- Configurar backups automáticos
- Monitorear logs
- Configurar alertas

---

Para más detalles sobre endpoints y estructura de datos, ver `REFERENCIA_API.md`

