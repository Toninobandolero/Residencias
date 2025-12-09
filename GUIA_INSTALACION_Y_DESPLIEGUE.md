# 📦 Guía de Instalación y Despliegue

## 📋 Tabla de Contenidos

1. [Instalación Local](#instalación-local)
2. [Configuración Local](#configuración-local)
3. [Despliegue a Cloud Run](#despliegue-a-cloud-run)
4. [Configuración de Permisos IAM](#configuración-de-permisos-iam)
5. [Verificación Post-Despliegue](#verificación-post-despliegue)

---

## 🚀 Instalación Local

### Requisitos Previos

- **Python 3.11 o superior**
- **pip** (gestor de paquetes de Python)
- **PowerShell** (Windows) o terminal similar
- **Credenciales de Google Cloud Platform** (archivo JSON)
- **Acceso a Cloud SQL** (PostgreSQL en GCP)

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
- openpyxl

---

## ⚙️ Configuración Local

### Variables de Entorno

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
GCS_BUCKET_NAME=violetas-documentos
GCS_PROJECT_ID=residencias-479706
```

**⚠️ IMPORTANTE:**
- El archivo `.env` NO debe versionarse (ya está en `.gitignore`)
- Nunca compartas tus credenciales

### Configurar Cloud SQL Proxy (Recomendado)

**Ventajas:**
- ✅ No necesitas autorizar IPs cada vez que cambias de ubicación
- ✅ Funciona desde cualquier lugar
- ✅ Más seguro (conexión encriptada)
- ✅ Recomendado por Google Cloud

**Instalación Automática:**

```powershell
# 1. Configurar Cloud SQL Proxy
.\setup_cloud_sql_proxy.ps1

# 2. Configurar .env automáticamente
.\configurar_proxy_env.ps1

# 3. Iniciar servidor (inicia proxy y Flask juntos)
.\start_server_with_proxy.ps1
```

**Instalación Manual:**

1. **Descargar Cloud SQL Proxy:**
   - URL: https://github.com/GoogleCloudPlatform/cloud-sql-proxy/releases
   - Archivo: `cloud-sql-proxy.x64.exe` (Windows)
   - Guardar en: `cloud-sql-proxy/cloud_sql_proxy.exe`

2. **Obtener Credenciales JSON de GCP:**
   - Ir a: https://console.cloud.google.com/apis/credentials
   - Crear cuenta de servicio o usar existente
   - Descargar clave JSON
   - Guardar en directorio del proyecto

3. **Iniciar proxy manualmente:**
   ```powershell
   .\cloud-sql-proxy\cloud_sql_proxy.exe --port=5432 --address=127.0.0.1 residencias-479706:europe-west9:residencias
   ```

### Crear Base de Datos

```powershell
python create_database.py
```

Este script:
- Lee `create_schema.sql`
- Crea todas las tablas necesarias
- Inserta datos iniciales (residencias, roles)

### Crear Super Administrador

```powershell
python init_database.py
```

**Credenciales por defecto:**
- Email: `admin@residencias.com`
- Password: `CambiarContraseña123!`
- ⚠️ **IMPORTANTE**: Deberás cambiar la contraseña en el primer login

### Iniciar Servidor Local

**Opción 1: Con Cloud SQL Proxy (Recomendado)**

```powershell
.\start_server_with_proxy.ps1
```

**Opción 2: Sin Proxy (Conexión Directa)**

```powershell
.\start_server.ps1
```

**Requisitos:**
- IP autorizada en Cloud SQL
- Variables de entorno configuradas (`DB_USE_PROXY=false`)

**Verificar que Funciona:**

1. Health Check:
   ```bash
   curl http://localhost:5001/health
   ```

2. Abrir navegador:
   - URL: http://localhost:5001
   - **Nota**: El puerto 5001 se usa por defecto para evitar conflictos con AirPlay en macOS. Puedes cambiarlo con la variable `PORT`.

---

## ☁️ Despliegue a Cloud Run

### Requisitos Previos

- **Google Cloud SDK** instalado y configurado
- **Proyecto GCP** configurado: `residencias-479706`
- **Secrets creados** en Secret Manager (ver sección siguiente)
- **Permisos IAM** otorgados (ver sección siguiente)

### Archivos Necesarios

Asegúrate de tener estos archivos en la raíz del proyecto:

- ✅ `app.py` - Aplicación Flask principal
- ✅ `Procfile` - Comando de inicio para Cloud Run
- ✅ `requirements.txt` - Dependencias Python
- ✅ `runtime.txt` - Versión de Python (debe contener: `python-3.11`)

### Crear Secrets en Secret Manager

**Secret 1: jwt-secret-key**

```powershell
# Crear secret
echo "tu-clave-secreta-muy-segura" | gcloud secrets create jwt-secret-key --data-file=- --project=residencias-479706

# O si ya existe, actualizar versión
echo "tu-clave-secreta-muy-segura" | gcloud secrets versions add jwt-secret-key --data-file=- --project=residencias-479706
```

**Secret 2: db-password**

```powershell
# Crear secret
echo "tu-contraseña-de-bd" | gcloud secrets create db-password --data-file=- --project=residencias-479706

# O si ya existe, actualizar versión
echo "tu-contraseña-de-bd" | gcloud secrets versions add db-password --data-file=- --project=residencias-479706
```

**Verificar que existen:**

```powershell
gcloud secrets list --project=residencias-479706
```

Debes ver:
- `jwt-secret-key`
- `db-password`

### Desplegar a Cloud Run

**Método 1: Script Automatizado (Recomendado)**

```powershell
.\deploy_mejorado.bat
```

Este script:
- ✅ Verifica archivos críticos
- ✅ Verifica sintaxis de Python
- ✅ Verifica que los secrets existen
- ✅ Despliega a Cloud Run
- ✅ Verifica health check

**Método 2: Comando Manual**

```powershell
gcloud run deploy violetas-app `
    --source . `
    --region europe-west9 `
    --platform managed `
    --allow-unauthenticated `
    --add-cloudsql-instances residencias-479706:europe-west9:residencias `
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias,GCS_BUCKET_NAME=violetas-documentos" `
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" `
    --memory 2Gi `
    --cpu 2 `
    --timeout 300 `
    --max-instances 10 `
    --min-instances 0 `
    --project=residencias-479706
```

### Configuración del Procfile

El archivo `Procfile` debe contener:

```
web: gunicorn app:app --bind 0.0.0.0:$PORT
```

**Explicación:**
- `web:` - Tipo de proceso (requerido por Cloud Run)
- `gunicorn` - Servidor WSGI para Python
- `app:app` - Módulo `app.py`, variable `app`
- `--bind 0.0.0.0:$PORT` - Escuchar en todas las interfaces, puerto desde variable de entorno

---

## 🔐 Configuración de Permisos IAM

### Cuenta de Servicio

Cloud Run usa una cuenta de servicio para acceder a recursos de GCP. Por defecto usa:

```
621063984498-compute@developer.gserviceaccount.com
```

**Obtener cuenta de servicio:**

```powershell
$sa = gcloud run services describe violetas-app --region europe-west9 --project residencias-479706 --format="value(spec.template.spec.serviceAccountName)"
if (-not $sa) { 
    $pn = gcloud projects describe residencias-479706 --format="value(projectNumber)"
    $sa = "$pn-compute@developer.gserviceaccount.com" 
}
Write-Host "Cuenta de servicio: $sa"
```

### Permisos Necesarios

La aplicación necesita **4 permisos** en total:

#### 1. Secret Manager - jwt-secret-key

**Desde PowerShell:**

```powershell
# Obtener cuenta de servicio
$pn = gcloud projects describe residencias-479706 --format="value(projectNumber)"
$sa = "$pn-compute@developer.gserviceaccount.com"

# Otorgar permiso
gcloud secrets add-iam-policy-binding jwt-secret-key `
    --member "serviceAccount:$sa" `
    --role "roles/secretmanager.secretAccessor" `
    --project=residencias-479706
```

**Desde Consola Web:**

1. Ve a: https://console.cloud.google.com/security/secret-manager/secret/jwt-secret-key?project=residencias-479706
2. Click en la pestaña **"PERMISOS"**
3. Click en **"AGREGAR PRINCIPAL"**
4. Pega: `621063984498-compute@developer.gserviceaccount.com`
5. Rol: **"Usuario con acceso a secretos"** (o "Secret Manager Secret Accessor")
6. Click **"GUARDAR"**

#### 2. Secret Manager - db-password

**Desde PowerShell:**

```powershell
gcloud secrets add-iam-policy-binding db-password `
    --member "serviceAccount:$sa" `
    --role "roles/secretmanager.secretAccessor" `
    --project=residencias-479706
```

**Desde Consola Web:**

1. Ve a: https://console.cloud.google.com/security/secret-manager/secret/db-password?project=residencias-479706
2. Repite los mismos pasos que para jwt-secret-key

#### 3. Cloud SQL

**Desde PowerShell:**

```powershell
gcloud projects add-iam-policy-binding residencias-479706 `
    --member "serviceAccount:$sa" `
    --role "roles/cloudsql.client"
```

**Desde Consola Web:**

1. Ve a: https://console.cloud.google.com/iam-admin/iam?project=residencias-479706
2. Busca la cuenta: `621063984498-compute@developer.gserviceaccount.com`
3. Click en editar (lápiz)
4. Click en **"AGREGAR OTRO ROL"**
5. Rol: **"Cliente de Cloud SQL"** (o "Cloud SQL Client")
6. Click **"GUARDAR"**

#### 4. Cloud Storage

**Desde PowerShell:**

```powershell
gcloud projects add-iam-policy-binding residencias-479706 `
    --member "serviceAccount:$sa" `
    --role "roles/storage.objectAdmin"
```

**Desde Consola Web:**

1. En la misma página de IAM (https://console.cloud.google.com/iam-admin/iam?project=residencias-479706)
2. Busca la misma cuenta
3. Click en editar (lápiz)
4. Click en **"AGREGAR OTRO ROL"**
5. Rol: **"Administrador de objetos de Storage"** (o "Storage Object Admin")
6. Click **"GUARDAR"**

### Script para Otorgar Todos los Permisos

```powershell
# Obtener cuenta de servicio
$pn = gcloud projects describe residencias-479706 --format="value(projectNumber)"
$sa = "$pn-compute@developer.gserviceaccount.com"

Write-Host "Otorgando permisos a: $sa" -ForegroundColor Cyan

# Secrets
gcloud secrets add-iam-policy-binding jwt-secret-key --member "serviceAccount:$sa" --role "roles/secretmanager.secretAccessor" --project=residencias-479706
gcloud secrets add-iam-policy-binding db-password --member "serviceAccount:$sa" --role "roles/secretmanager.secretAccessor" --project=residencias-479706

# Cloud SQL
gcloud projects add-iam-policy-binding residencias-479706 --member "serviceAccount:$sa" --role "roles/cloudsql.client"

# Cloud Storage
gcloud projects add-iam-policy-binding residencias-479706 --member "serviceAccount:$sa" --role "roles/storage.objectAdmin"

Write-Host "✅ Permisos otorgados" -ForegroundColor Green
```

### Verificar Permisos

**Verificar secrets:**

```powershell
gcloud secrets get-iam-policy jwt-secret-key --project=residencias-479706
gcloud secrets get-iam-policy db-password --project=residencias-479706
```

**Verificar IAM:**

```powershell
gcloud projects get-iam-policy residencias-479706 --flatten="bindings[].members" --filter="bindings.members:serviceAccount:$sa"
```

---

## ✅ Verificación Post-Despliegue

### 1. Obtener URL del Servicio

```powershell
gcloud run services describe violetas-app --region europe-west9 --format="value(status.url)" --project=residencias-479706
```

### 2. Health Check

```powershell
$url = gcloud run services describe violetas-app --region europe-west9 --format="value(status.url)" --project=residencias-479706
curl "$url/health"
```

Debe retornar: `{"status": "ok"}`

### 3. Ver Logs

**Desde PowerShell:**

```powershell
.\obtener_logs_produccion.ps1
```

**Desde línea de comandos:**

```powershell
gcloud run services logs read violetas-app --region europe-west9 --project residencias-479706 --limit 50
```

**Logs en tiempo real:**

```powershell
gcloud run services logs tail violetas-app --region europe-west9 --project residencias-479706
```

**Desde Consola Web:**

1. Ve a: https://console.cloud.google.com/run/detail/europe-west9/violetas-app/logs?project=residencias-479706
2. Verás todos los logs del servicio

### 4. Probar Login

```powershell
$url = gcloud run services describe violetas-app --region europe-west9 --format="value(status.url)" --project=residencias-479706

curl -X POST "$url/api/v1/login" `
    -H "Content-Type: application/json" `
    -d '{"email":"admin@residencias.com","password":"CambiarContraseña123!"}'
```

Debe retornar un token JWT.

---

## 🔍 Solución de Problemas Comunes

### Error: "Container import failed"

**Causas posibles:**
1. ❌ Faltan permisos IAM
2. ❌ Secrets no existen o no tienen permisos
3. ❌ Error de sintaxis en `app.py`
4. ❌ Dependencias faltantes en `requirements.txt`

**Solución:**

1. **Verificar sintaxis:**
   ```powershell
   python -m py_compile app.py
   ```

2. **Verificar secrets:**
   ```powershell
   gcloud secrets list --project=residencias-479706
   ```

3. **Verificar permisos:**
   - Ver sección "Configuración de Permisos IAM" arriba

4. **Ver logs:**
   ```powershell
   .\obtener_logs_produccion.ps1
   ```

### Error: "Secret not found"

**Solución:**

```powershell
# Crear secrets si no existen
echo "tu-clave-secreta" | gcloud secrets create jwt-secret-key --data-file=- --project=residencias-479706
echo "tu-contraseña" | gcloud secrets create db-password --data-file=- --project=residencias-479706

# Otorgar permisos (ver sección de permisos arriba)
```

### Error: "Cloud SQL connection failed"

**Solución:**

1. Verificar que `--add-cloudsql-instances` está en el comando de despliegue
2. Verificar permisos IAM de Cloud SQL
3. Verificar que la instancia existe y está activa

### Error: "Permission denied" en Storage

**Solución:**

1. Verificar permisos IAM de Cloud Storage
2. Verificar que el bucket existe: `gsutil ls gs://violetas-documentos`

---

## 📋 Checklist de Despliegue

- [ ] Secrets creados (`jwt-secret-key`, `db-password`)
- [ ] Permisos IAM otorgados (4 permisos)
- [ ] Archivos críticos presentes (`app.py`, `Procfile`, `requirements.txt`, `runtime.txt`)
- [ ] Sintaxis de Python verificada
- [ ] Despliegue exitoso
- [ ] Health check OK
- [ ] Login funciona
- [ ] Logs sin errores

---

Para más detalles sobre troubleshooting, ver `GUIA_TROUBLESHOOTING.md`

