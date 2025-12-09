# 🔧 Guía de Troubleshooting

## 📋 Tabla de Contenidos

1. [Problemas de Instalación Local](#problemas-de-instalación-local)
2. [Problemas de Conexión a Base de Datos](#problemas-de-conexión-a-base-de-datos)
3. [Problemas de Despliegue en Cloud Run](#problemas-de-despliegue-en-cloud-run)
4. [Problemas de Permisos IAM](#problemas-de-permisos-iam)
5. [Problemas de Autenticación](#problemas-de-autenticación)
6. [Cómo Ver Logs](#cómo-ver-logs)
7. [Errores Comunes y Soluciones](#errores-comunes-y-soluciones)

---

## 🚀 Problemas de Instalación Local

### Error: "Faltan variables de entorno"

**Síntomas:**
- La aplicación no inicia
- Errores sobre variables no definidas

**Solución:**

1. Verificar que el archivo `.env` existe en la raíz del proyecto
2. Verificar que contiene todas las variables necesarias:
   ```env
   DB_NAME=postgres
   DB_USER=postgres
   DB_PASSWORD=tu-contraseña
   DB_PORT=5432
   DB_USE_PROXY=true
   DB_HOST=127.0.0.1
   CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias
   GOOGLE_APPLICATION_CREDENTIALS=residencias-479706-8c3bdbf8bbf8.json
   JWT_SECRET_KEY=tu-clave-secreta
   GCS_BUCKET_NAME=violetas-documentos
   ```

### Error: "ModuleNotFoundError"

**Síntomas:**
- Error al importar módulos
- Dependencias faltantes

**Solución:**

```powershell
# Reinstalar dependencias
pip install -r requirements.txt

# Verificar que todas las dependencias están instaladas
pip list
```

### Error: "Python version not supported"

**Síntomas:**
- Error sobre versión de Python incorrecta

**Solución:**

1. Verificar versión de Python:
   ```powershell
   python --version
   ```
   Debe ser Python 3.11 o superior

2. Si no tienes Python 3.11+, instálalo desde: https://www.python.org/downloads/

---

## 🗄️ Problemas de Conexión a Base de Datos

### Error: "Connection timed out"

**Síntomas:**
- No se puede conectar a Cloud SQL
- Timeout en conexión

**Causas posibles:**
1. IP no autorizada (si usas conexión directa)
2. Cloud SQL Proxy no iniciado (si usas proxy)
3. Credenciales incorrectas

**Solución 1: Usar Cloud SQL Proxy (Recomendado)**

```powershell
# 1. Configurar Cloud SQL Proxy
.\setup_cloud_sql_proxy.ps1

# 2. Configurar .env
.\configurar_proxy_env.ps1

# 3. Iniciar servidor con proxy
.\start_server_with_proxy.ps1
```

**Solución 2: Autorizar IP en Cloud SQL**

1. Obtener tu IP pública:
   ```powershell
   python obtener_mi_ip.py
   ```

2. Autorizar IP en Cloud SQL Console:
   - Ve a: https://console.cloud.google.com/sql/instances/residencias/overview
   - Click en "CONNECTIONS" → "NETWORKING"
   - Click en "ADD NETWORK"
   - Agrega: `TU_IP/32`
   - Click "SAVE"

### Error: "Failed to get instance" (Proxy)

**Síntomas:**
- Cloud SQL Proxy no puede conectarse
- Error sobre instancia no encontrada

**Causa:** `CLOUD_SQL_CONNECTION_NAME` incorrecto

**Solución:**

1. Verificar formato: `PROYECTO:REGION:INSTANCIA`
   - Ejemplo: `residencias-479706:europe-west9:residencias`

2. Verificar en `.env`:
   ```env
   CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias
   ```

3. Verificar que la instancia existe:
   ```powershell
   gcloud sql instances list --project=residencias-479706
   ```

### Error: "Failed to get credentials" (Proxy)

**Síntomas:**
- Cloud SQL Proxy no puede autenticarse
- Error sobre credenciales

**Causa:** Archivo JSON de credenciales no encontrado o inválido

**Solución:**

1. Verificar que el archivo existe:
   ```powershell
   Test-Path residencias-479706-8c3bdbf8bbf8.json
   ```

2. Verificar en `.env`:
   ```env
   GOOGLE_APPLICATION_CREDENTIALS=residencias-479706-8c3bdbf8bbf8.json
   ```

3. Si no existe, descargar desde:
   - https://console.cloud.google.com/apis/credentials
   - Crear cuenta de servicio o usar existente
   - Descargar clave JSON

### Error: "Puerto 5432 ya en uso"

**Síntomas:**
- No se puede iniciar Cloud SQL Proxy
- Puerto ocupado

**Solución:**

1. Cambiar puerto del proxy:
   - Editar `start_server_with_proxy.ps1`: `--port=5433`
   - Actualizar `.env`: `DB_PORT=5433`

2. O cerrar el proceso que usa el puerto:
   ```powershell
   # Ver qué proceso usa el puerto
   netstat -ano | findstr :5432
   
   # Cerrar proceso (reemplazar PID con el número)
   taskkill /PID <PID> /F
   ```

---

## ☁️ Problemas de Despliegue en Cloud Run

### Error: "Container import failed"

**Síntomas:**
- El despliegue parece exitoso pero el contenedor no inicia
- Error genérico sin detalles

**Causas posibles:**
1. ❌ Faltan permisos IAM
2. ❌ Secrets no existen o no tienen permisos
3. ❌ Error de sintaxis en `app.py`
4. ❌ Dependencias faltantes en `requirements.txt`

**Solución paso a paso:**

1. **Verificar sintaxis de Python:**
   ```powershell
   python -m py_compile app.py
   ```
   Si hay errores, corregirlos antes de redesplegar.

2. **Verificar archivos críticos:**
   - ✅ `app.py` existe
   - ✅ `Procfile` existe y contiene: `web: gunicorn app:app --bind 0.0.0.0:$PORT`
   - ✅ `requirements.txt` existe y contiene todas las dependencias
   - ✅ `runtime.txt` existe y contiene: `python-3.11`

3. **Verificar secrets:**
   ```powershell
   gcloud secrets list --project=residencias-479706
   ```
   Debes ver:
   - `jwt-secret-key`
   - `db-password`

4. **Verificar permisos IAM:**
   - Ver sección "Problemas de Permisos IAM" abajo

5. **Ver logs:**
   ```powershell
   .\obtener_logs_produccion.ps1
   ```
   O desde consola web:
   - https://console.cloud.google.com/run/detail/europe-west9/violetas-app/logs?project=residencias-479706

### Error: "Secret not found"

**Síntomas:**
- Error al iniciar contenedor
- Mensaje sobre secret no encontrado

**Solución:**

1. **Crear secrets si no existen:**
   ```powershell
   echo "tu-clave-secreta" | gcloud secrets create jwt-secret-key --data-file=- --project=residencias-479706
   echo "tu-contraseña" | gcloud secrets create db-password --data-file=- --project=residencias-479706
   ```

2. **Verificar que existen:**
   ```powershell
   gcloud secrets list --project=residencias-479706
   ```

3. **Otorgar permisos:**
   - Ver sección "Problemas de Permisos IAM" abajo

### Error: "Cloud SQL connection failed"

**Síntomas:**
- No se puede conectar a Cloud SQL desde Cloud Run
- Timeout o error de conexión

**Solución:**

1. **Verificar que `--add-cloudsql-instances` está en el comando de despliegue:**
   ```powershell
   --add-cloudsql-instances residencias-479706:europe-west9:residencias
   ```

2. **Verificar permisos IAM de Cloud SQL:**
   ```powershell
   $pn = gcloud projects describe residencias-479706 --format="value(projectNumber)"
   $sa = "$pn-compute@developer.gserviceaccount.com"
   
   gcloud projects get-iam-policy residencias-479706 --flatten="bindings[].members" --filter="bindings.members:serviceAccount:$sa" | Select-String "cloudsql"
   ```
   Debe mostrar `roles/cloudsql.client`

3. **Verificar que la instancia existe y está activa:**
   ```powershell
   gcloud sql instances describe residencias --project=residencias-479706
   ```

### Error: "Permission denied" en Storage

**Síntomas:**
- Error al subir/descargar documentos
- Error de permisos en Cloud Storage

**Solución:**

1. **Verificar permisos IAM de Cloud Storage:**
   ```powershell
   $pn = gcloud projects describe residencias-479706 --format="value(projectNumber)"
   $sa = "$pn-compute@developer.gserviceaccount.com"
   
   gcloud projects get-iam-policy residencias-479706 --flatten="bindings[].members" --filter="bindings.members:serviceAccount:$sa" | Select-String "storage"
   ```
   Debe mostrar `roles/storage.objectAdmin`

2. **Otorgar permiso si falta:**
   ```powershell
   gcloud projects add-iam-policy-binding residencias-479706 --member "serviceAccount:$sa" --role "roles/storage.objectAdmin"
   ```

3. **Verificar que el bucket existe:**
   ```powershell
   gsutil ls gs://violetas-documentos
   ```

---

## 🔐 Problemas de Permisos IAM

### Error: "Permission denied" al leer secrets

**Síntomas:**
- Error al iniciar contenedor
- No puede leer secrets

**Solución:**

1. **Obtener cuenta de servicio:**
   ```powershell
   $pn = gcloud projects describe residencias-479706 --format="value(projectNumber)"
   $sa = "$pn-compute@developer.gserviceaccount.com"
   Write-Host "Cuenta: $sa"
   ```

2. **Otorgar permisos a cada secret:**
   ```powershell
   gcloud secrets add-iam-policy-binding jwt-secret-key --member "serviceAccount:$sa" --role "roles/secretmanager.secretAccessor" --project=residencias-479706
   
   gcloud secrets add-iam-policy-binding db-password --member "serviceAccount:$sa" --role "roles/secretmanager.secretAccessor" --project=residencias-479706
   ```

3. **Verificar permisos:**
   ```powershell
   gcloud secrets get-iam-policy jwt-secret-key --project=residencias-479706
   gcloud secrets get-iam-policy db-password --project=residencias-479706
   ```

### Error: "Permission denied" en Cloud SQL

**Solución:**

```powershell
$pn = gcloud projects describe residencias-479706 --format="value(projectNumber)"
$sa = "$pn-compute@developer.gserviceaccount.com"

gcloud projects add-iam-policy-binding residencias-479706 --member "serviceAccount:$sa" --role "roles/cloudsql.client"
```

### Error: "Permission denied" en Cloud Storage

**Solución:**

```powershell
$pn = gcloud projects describe residencias-479706 --format="value(projectNumber)"
$sa = "$pn-compute@developer.gserviceaccount.com"

gcloud projects add-iam-policy-binding residencias-479706 --member "serviceAccount:$sa" --role "roles/storage.objectAdmin"
```

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

---

## 🔑 Problemas de Autenticación

### Error: "Credenciales inválidas"

**Síntomas:**
- No se puede hacer login
- Error 401

**Solución:**

1. **Verificar credenciales:**
   - Email correcto
   - Contraseña correcta (mayúsculas/minúsculas importan)

2. **Verificar que el usuario existe:**
   ```python
   from db_connector import get_db_connection
   
   conn = get_db_connection()
   cursor = conn.cursor()
   cursor.execute("SELECT email, id_rol FROM usuario WHERE email = %s", ("admin@residencias.com",))
   usuario = cursor.fetchone()
   print(usuario)
   cursor.close()
   conn.close()
   ```

3. **Resetear contraseña si es necesario:**
   ```powershell
   python reset_superadmin_password.py
   ```

### Error: "Token expirado"

**Síntomas:**
- Token válido pero expirado
- Error 401 después de un tiempo

**Solución:**

1. **Hacer login nuevamente** para obtener un nuevo token
2. **Los tokens expiran después de 24 horas** (configuración por diseño)

### Error: "Requiere cambio de contraseña"

**Síntomas:**
- Login exitoso pero acceso bloqueado
- Mensaje sobre cambio de contraseña obligatorio

**Solución:**

1. **Cambiar contraseña mediante API:**
   ```powershell
   # Primero hacer login para obtener token
   $response = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/login" -Method POST -Body '{"email":"admin@residencias.com","password":"CambiarContraseña123!"}' -ContentType "application/json"
   $token = $response.token
   
   # Cambiar contraseña
   Invoke-RestMethod -Uri "http://localhost:5000/api/v1/usuario/cambio-clave" -Method POST -Headers @{"Authorization"="Bearer $token"} -Body '{"clave_actual":"CambiarContraseña123!","clave_nueva":"NuevaContraseña456!"}' -ContentType "application/json"
   ```

2. **O resetear desde base de datos:**
   ```sql
   UPDATE usuario SET requiere_cambio_clave = FALSE WHERE email = 'admin@residencias.com';
   ```

---

## 📊 Cómo Ver Logs

### Logs Locales

Los logs se muestran en la terminal donde ejecutas el servidor.

### Logs de Cloud Run

**Desde PowerShell:**

```powershell
# Ver últimos 50 logs
.\obtener_logs_produccion.ps1

# O manualmente
gcloud run services logs read violetas-app --region europe-west9 --project residencias-479706 --limit 50
```

**Logs en tiempo real:**

```powershell
gcloud run services logs tail violetas-app --region europe-west9 --project residencias-479706
```

**Desde Consola Web:**

1. **Logs del Servicio (MÁS IMPORTANTE):**
   - URL: https://console.cloud.google.com/run/detail/europe-west9/violetas-app/logs?project=residencias-479706
   - Muestra todos los logs del servicio, incluyendo errores de inicio

2. **Logs de Construcción (Build Logs):**
   - URL: https://console.cloud.google.com/cloud-build/builds?project=residencias-479706
   - Busca el build más reciente
   - Click para ver logs completos

3. **Logs de Auditoría:**
   - URL: https://console.cloud.google.com/logs/query?project=residencias-479706
   - Query recomendada:
     ```
     resource.type="cloud_run_revision"
     resource.labels.service_name="violetas-app"
     severity>=ERROR
     ```

### Qué Buscar en los Logs

**En Logs del Servicio:**
- Errores al iniciar gunicorn
- Errores de importación de módulos
- Errores de conexión a base de datos
- Errores relacionados con secrets

**En Logs de Build:**
- Errores durante la construcción
- Problemas con dependencias
- Errores en el Procfile
- Problemas con el entrypoint

---

## 🐛 Errores Comunes y Soluciones

### Error: "IndentationError"

**Síntomas:**
- Error de sintaxis en Python
- Indentación incorrecta

**Solución:**

1. **Verificar sintaxis:**
   ```powershell
   python -m py_compile app.py
   ```

2. **Corregir indentación** según el error mostrado
3. **Usar espacios consistentes** (4 espacios por nivel)

### Error: "No se puede cargar el archivo ... porque la ejecución de scripts está deshabilitada"

**Síntomas:**
- No se pueden ejecutar scripts `.ps1`
- Error `PSSecurityException`

**Solución:**

**Opción 1: Cambiar política de ejecución**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Opción 2: Usar archivo .bat**

```powershell
.\deploy_mejorado.bat
```

### Error: "gcloud no se reconoce como comando"

**Síntomas:**
- No se encuentra `gcloud`
- Error al ejecutar comandos de Google Cloud

**Solución:**

1. **Instalar Google Cloud SDK:**
   - https://cloud.google.com/sdk/docs/install

2. **O usar ruta completa:**
   ```powershell
   $gcloudPath = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"
   & $gcloudPath run services list
   ```

### Error: "No se listan los residentes"

**Síntomas:**
- Login exitoso pero lista vacía
- No aparecen datos

**Solución:**

1. **Verificar token en localStorage:**
   - F12 → Console → `localStorage.getItem('token')`

2. **Verificar que hay residentes en la BD:**
   ```python
   from db_connector import get_db_connection
   
   conn = get_db_connection()
   cursor = conn.cursor()
   cursor.execute("SELECT COUNT(*) FROM residente")
   count = cursor.fetchone()[0]
   print(f"Total residentes: {count}")
   cursor.close()
   conn.close()
   ```

3. **Verificar residencias asignadas al usuario:**
   ```python
   cursor.execute("""
       SELECT ur.id_residencia, r.nombre 
       FROM usuario_residencia ur
       JOIN residencia r ON ur.id_residencia = r.id_residencia
       WHERE ur.id_usuario = %s
   """, (id_usuario,))
   ```

---

## 📋 Checklist de Troubleshooting

Cuando algo no funciona, revisa en este orden:

- [ ] **Sintaxis de Python:** `python -m py_compile app.py`
- [ ] **Archivo .env:** Existe y tiene todas las variables
- [ ] **Dependencias:** `pip install -r requirements.txt`
- [ ] **Conexión a BD:** Proxy iniciado o IP autorizada
- [ ] **Secrets:** Existen y tienen permisos
- [ ] **Permisos IAM:** Todos los 4 permisos otorgados
- [ ] **Logs:** Revisar logs para errores específicos
- [ ] **Health check:** `curl http://localhost:5000/health` o URL de producción

---

Para más detalles sobre instalación y despliegue, ver `GUIA_INSTALACION_Y_DESPLIEGUE.md`

