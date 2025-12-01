# 📦 Guía de Instalación y Configuración

## 📋 Tabla de Contenidos

1. [Requisitos Previos](#requisitos-previos)
2. [Instalación Inicial](#instalación-inicial)
3. [Configuración de Variables de Entorno](#configuración-de-variables-de-entorno)
4. [Configuración de Cloud SQL Proxy](#configuración-de-cloud-sql-proxy)
5. [Configuración de Base de Datos](#configuración-de-base-de-datos)
6. [Crear Super Administrador](#crear-super-administrador)
7. [Iniciar el Servidor](#iniciar-el-servidor)

---

## 🔧 Requisitos Previos

- **Python 3.11 o superior**
- **pip** (gestor de paquetes de Python)
- **PowerShell** (Windows) o terminal similar
- **Credenciales de Google Cloud Platform** (archivo JSON)
- **Acceso a Cloud SQL** (PostgreSQL en GCP)

---

## 🚀 Instalación Inicial

### 1. Clonar el Repositorio

```powershell
git clone https://github.com/Toninobandolero/Residencias.git
cd Residencias
```

### 2. Instalar Dependencias

```powershell
pip install -r requirements.txt
```

**Dependencias principales:**
- Flask
- PyJWT
- psycopg2-binary
- python-dotenv
- Werkzeug
- google-cloud-storage

---

## ⚙️ Configuración de Variables de Entorno

Crear archivo `.env` en la raíz del proyecto:

```env
# Base de Datos
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=tu-contraseña
DB_PORT=5432

# Opción A: Con Cloud SQL Proxy (Recomendado)
DB_USE_PROXY=true
DB_HOST=127.0.0.1
CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias
GOOGLE_APPLICATION_CREDENTIALS=residencias-479706-8c3bdbf8bbf8.json

# Opción B: Conexión Directa (Requiere autorizar IP)
# DB_USE_PROXY=false
# DB_HOST=34.155.185.9

# Autenticación JWT
JWT_SECRET_KEY=tu-clave-secreta-muy-segura

# Super Admin (Opcional - valores por defecto si no se especifican)
SUPER_ADMIN_EMAIL=admin@residencias.com
SUPER_ADMIN_PASSWORD=CambiarContraseña123!

# Google Cloud Storage (para documentos)
GCS_BUCKET_NAME=residencias-documentos
GCS_PROJECT_ID=residencias-479706
```

**⚠️ IMPORTANTE:**
- El archivo `.env` NO debe versionarse (ya está en `.gitignore`)
- Nunca compartas tus credenciales

---

## 🔧 Configuración de Cloud SQL Proxy

### ¿Por Qué Cloud SQL Proxy?

**Ventajas:**
- ✅ No necesitas autorizar IPs cada vez que cambias de ubicación
- ✅ Funciona desde cualquier lugar
- ✅ Más seguro (conexión encriptada)
- ✅ Recomendado por Google Cloud

### Instalación Automática

```powershell
# 1. Configurar Cloud SQL Proxy
.\setup_cloud_sql_proxy.ps1

# 2. Configurar .env automáticamente
.\configurar_proxy_env.ps1

# 3. Iniciar servidor (inicia proxy y Flask juntos)
.\start_server_with_proxy.ps1
```

### Instalación Manual

1. **Descargar Cloud SQL Proxy:**
   - URL: https://github.com/GoogleCloudPlatform/cloud-sql-proxy/releases
   - Archivo: `cloud-sql-proxy.x64.exe` (Windows)
   - Guardar en: `cloud-sql-proxy/cloud_sql_proxy.exe`

2. **Obtener Credenciales JSON de GCP:**
   - Ir a: https://console.cloud.google.com/apis/credentials
   - Crear cuenta de servicio o usar existente
   - Descargar clave JSON
   - Guardar en directorio del proyecto (ej: `residencias-479706-8c3bdbf8bbf8.json`)

3. **Configurar .env:**
   ```env
   DB_USE_PROXY=true
   DB_HOST=127.0.0.1
   DB_PORT=5432
   CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias
   GOOGLE_APPLICATION_CREDENTIALS=residencias-479706-8c3bdbf8bbf8.json
   ```

4. **Iniciar proxy manualmente:**
   ```powershell
   .\cloud-sql-proxy\cloud_sql_proxy.exe --port=5432 --address=127.0.0.1 residencias-479706:europe-west9:residencias
   ```

### Verificación

```powershell
# Verificar que el proxy está corriendo
Get-Process | Where-Object {$_.ProcessName -like "*cloud_sql*"}

# Probar conexión
python test_conexion_bd.py
```

---

## 🗄️ Configuración de Base de Datos

### Crear Esquema

```powershell
python create_database.py
```

Este script:
- Lee `create_schema.sql`
- Crea todas las tablas necesarias
- Inserta datos iniciales (residencias, roles)

### Estructura de Tablas Principales

- `residencia` - Residencias (Violetas 1 y Violetas 2)
- `rol` - Roles de usuario (super_admin, Administrador, Director, Personal)
- `usuario` - Usuarios del sistema
- `usuario_residencia` - Relación muchos a muchos (usuarios ↔ residencias)
- `permiso` - Permisos granulares del sistema
- `rol_permiso` - Relación entre roles y permisos
- `residente` - Residentes
- `pago_residente` - Pagos de residentes
- `proveedor` - Proveedores
- `pago_proveedor` - Pagos a proveedores
- `personal` - Personal de la residencia
- `documento_residente` - Documentos adjuntos

### Verificar Esquema

```python
from db_connector import get_db_connection

conn = get_db_connection()
cursor = conn.cursor()
cursor.execute("""
    SELECT table_name 
    FROM information_schema.tables 
    WHERE table_schema = 'public' 
    ORDER BY table_name
""")
tables = cursor.fetchall()
print("Tablas creadas:")
for table in tables:
    print(f"  - {table[0]}")
cursor.close()
conn.close()
```

---

## 👑 Crear Super Administrador

El sistema requiere un super administrador inicial para gestionar usuarios.

### Ejecutar Script de Inicialización

```powershell
python init_database.py
```

Este script:
- ✅ Crea el usuario super_admin con `id_rol = 1`
- ✅ Usa variables de entorno para email/contraseña (o valores por defecto)
- ✅ Verifica que no exista duplicado
- ✅ Requiere cambio de contraseña en primer login
- ✅ Agrega columna `requiere_cambio_clave` si no existe
- ✅ Actualiza el rol a `super_admin` si es necesario

### Credenciales por Defecto

Si no especificas en `.env`, usa:
- **Email**: `admin@residencias.com`
- **Password**: `CambiarContraseña123!`

### Personalizar Credenciales

Agregar al archivo `.env`:

```env
SUPER_ADMIN_EMAIL=tu_email@ejemplo.com
SUPER_ADMIN_PASSWORD=TuContraseñaSegura123!
```

Luego ejecutar: `python init_database.py`

### Verificar Creación

```python
from db_connector import get_db_connection

conn = get_db_connection()
cursor = conn.cursor()
cursor.execute("""
    SELECT id_usuario, email, id_rol, requiere_cambio_clave 
    FROM usuario 
    WHERE id_rol = 1
""")
super_admin = cursor.fetchone()
print(f"Super Admin: {super_admin}")
cursor.close()
conn.close()
```

---

## 🚀 Iniciar el Servidor

### Opción 1: Con Cloud SQL Proxy (Recomendado)

```powershell
.\start_server_with_proxy.ps1
```

Este script:
- Inicia Cloud SQL Proxy en segundo plano
- Espera a que el proxy esté listo
- Inicia Flask en el puerto 5000

### Opción 2: Sin Proxy (Conexión Directa)

```powershell
.\start_server.ps1
```

**Requisitos:**
- IP autorizada en Cloud SQL
- Variables de entorno configuradas (`DB_USE_PROXY=false`)

### Opción 3: Manual

```powershell
# Terminal 1: Iniciar proxy (si usas proxy)
.\cloud-sql-proxy\cloud_sql_proxy.exe --port=5432 --address=127.0.0.1 residencias-479706:europe-west9:residencias

# Terminal 2: Iniciar Flask
python app.py
```

### Verificar que Funciona

1. **Health Check:**
   ```bash
   curl http://localhost:5000/health
   ```

2. **Abrir navegador:**
   - URL: http://localhost:5000

3. **Ver logs:**
   - El servidor mostrará logs en la terminal
   - Verificar que no haya errores

---

## ✅ Checklist de Instalación

- [ ] Python 3.11+ instalado
- [ ] Dependencias instaladas (`pip install -r requirements.txt`)
- [ ] Archivo `.env` creado y configurado
- [ ] Credenciales JSON de GCP descargadas
- [ ] Cloud SQL Proxy configurado (si usas proxy)
- [ ] Base de datos creada (`python create_database.py`)
- [ ] Super admin creado (`python init_database.py`)
- [ ] Servidor iniciado y funcionando
- [ ] Acceso a http://localhost:5000

---

## 🔍 Solución de Problemas Comunes

### Error: "Faltan variables de entorno"

**Solución:** Verificar que el archivo `.env` existe y contiene todas las variables necesarias.

### Error: "Connection timed out"

**Causa:** IP no autorizada o proxy no iniciado.

**Solución 1:** Usar Cloud SQL Proxy
```powershell
.\setup_cloud_sql_proxy.ps1
.\start_server_with_proxy.ps1
```

**Solución 2:** Autorizar IP en Cloud SQL
1. Obtener IP: `python obtener_mi_ip.py`
2. Autorizar en: https://console.cloud.google.com/sql/instances/residencias/overview

### Error: "Failed to get instance" (Proxy)

**Causa:** `CLOUD_SQL_CONNECTION_NAME` incorrecto.

**Solución:** Verificar formato: `PROYECTO:REGION:INSTANCIA`

### Error: "Failed to get credentials" (Proxy)

**Causa:** Archivo JSON de credenciales no encontrado o inválido.

**Solución:** Verificar que `GOOGLE_APPLICATION_CREDENTIALS` apunte al archivo correcto.

### Puerto 5432 ya en uso

**Solución:** Cambiar puerto del proxy:
1. Editar `start_server_with_proxy.ps1`: `--port=5433`
2. Actualizar `.env`: `DB_PORT=5433`

---

Para más detalles sobre troubleshooting, ver `GUIA_TECNICA.md`

