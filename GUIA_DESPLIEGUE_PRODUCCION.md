# 🚀 Guía de Despliegue en Producción - Google Cloud Run

Esta guía te ayudará a desplegar la aplicación Flask de Gestión de Residencias Violetas en Google Cloud Run para producción.

## 📋 Tabla de Contenidos

1. [Requisitos Previos](#requisitos-previos)
2. [Preparación](#preparación)
3. [Configuración de Cloud SQL](#configuración-de-cloud-sql)
4. [Configuración de Secret Manager](#configuración-de-secret-manager)
5. [Build y Despliegue](#build-y-despliegue)
6. [Configuración de Variables de Entorno](#configuración-de-variables-de-entorno)
7. [Configuración de Dominio Personalizado](#configuración-de-dominio-personalizado)
8. [Monitoreo y Logs](#monitoreo-y-logs)
9. [Actualización de la Aplicación](#actualización-de-la-aplicación)
10. [Troubleshooting](#troubleshooting)

---

## ✅ Requisitos Previos

Antes de comenzar, asegúrate de tener:

- ✅ Cuenta de Google Cloud Platform activa
- ✅ Proyecto GCP creado (`residencias-479706`)
- ✅ Cloud SQL PostgreSQL configurado y funcionando
- ✅ Cloud Storage bucket creado
- ✅ Google Cloud SDK instalado (`gcloud`)
- ✅ Docker instalado (opcional, para build local)
- ✅ Permisos de administrador en el proyecto GCP

### Instalar Google Cloud SDK

```powershell
# Windows (usando Chocolatey)
choco install gcloudsdk

# O descargar desde:
# https://cloud.google.com/sdk/docs/install
```

### Autenticarse en GCP

```powershell
gcloud auth login
gcloud config set project residencias-479706
```

---

## 🔧 Preparación

### 1. Habilitar APIs Necesarias

```powershell
# Habilitar Cloud Run API
gcloud services enable run.googleapis.com

# Habilitar Cloud Build API (para builds automáticos)
gcloud services enable cloudbuild.googleapis.com

# Habilitar Secret Manager API (para credenciales)
gcloud services enable secretmanager.googleapis.com

# Habilitar Artifact Registry API (para almacenar imágenes Docker)
gcloud services enable artifactregistry.googleapis.com
```

### 2. Crear Artifact Registry (Repositorio de Imágenes Docker)

```powershell
# Crear repositorio para imágenes Docker
gcloud artifacts repositories create violetas-app \
    --repository-format=docker \
    --location=europe-west9 \
    --description="Repositorio de imágenes Docker para Violetas App"
```

---

## 🗄️ Configuración de Cloud SQL

### Conexión desde Cloud Run

Cloud Run se conecta a Cloud SQL usando **Unix sockets** (no necesita Cloud SQL Proxy).

1. **Obtener el nombre de conexión de Cloud SQL:**

```powershell
# Listar instancias de Cloud SQL
gcloud sql instances list

# El nombre de conexión tiene el formato:
# PROYECTO:REGION:INSTANCIA
# Ejemplo: residencias-479706:europe-west9:residencias
```

2. **Configurar Cloud SQL para Cloud Run:**

La conexión se configurará al desplegar el servicio (ver sección de despliegue).

---

## 🔐 Configuración de Secret Manager

En lugar de usar archivos JSON de credenciales, usaremos **Secret Manager** para mayor seguridad.

### 1. Crear Secretos

```powershell
# Crear secreto para JWT_SECRET_KEY
echo -n "TU_JWT_SECRET_KEY_MUY_SEGURO_AQUI" | gcloud secrets create jwt-secret-key --data-file=-

# Crear secreto para contraseña de BD
echo -n "TU_CONTRASEÑA_BD" | gcloud secrets create db-password --data-file=-

# Crear secreto para credenciales de cuenta de servicio (opcional)
# Si prefieres usar cuenta de servicio en lugar de Secret Manager
gcloud secrets create google-credentials --data-file=residencias-479706-8c3bdbf8bbf8.json
```

### 2. Otorgar Permisos a Cloud Run

```powershell
# Obtener el email de la cuenta de servicio de Cloud Run
$SERVICE_ACCOUNT = (gcloud iam service-accounts list --filter="displayName:Compute Engine default service account" --format="value(email)")

# Dar permisos para leer secretos
gcloud secrets add-iam-policy-binding jwt-secret-key \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding db-password \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor"
```

---

## 🐳 Build y Despliegue

### Opción A: Build y Despliegue desde Cloud Build (Recomendado)

Cloud Build construye la imagen Docker automáticamente y la despliega.

```powershell
# Desde el directorio del proyecto
gcloud run deploy violetas-app \
    --source . \
    --region europe-west9 \
    --platform managed \
    --allow-unauthenticated \
    --add-cloudsql-instances residencias-479706:europe-west9:residencias \
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false" \
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" \
    --set-env-vars "GOOGLE_APPLICATION_CREDENTIALS=/secrets/google-credentials" \
    --memory 1Gi \
    --cpu 1 \
    --timeout 300 \
    --max-instances 10 \
    --min-instances 1
```

### Opción B: Build Local y Push Manual

```powershell
# 1. Configurar Docker para usar gcloud como helper
gcloud auth configure-docker europe-west9-docker.pkg.dev

# 2. Build de la imagen
docker build -t europe-west9-docker.pkg.dev/residencias-479706/violetas-app/violetas-app:latest .

# 3. Push de la imagen
docker push europe-west9-docker.pkg.dev/residencias-479706/violetas-app/violetas-app:latest

# 4. Desplegar servicio
gcloud run deploy violetas-app \
    --image europe-west9-docker.pkg.dev/residencias-479706/violetas-app/violetas-app:latest \
    --region europe-west9 \
    --platform managed \
    --allow-unauthenticated \
    --add-cloudsql-instances residencias-479706:europe-west9:residencias \
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false" \
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" \
    --memory 1Gi \
    --cpu 1 \
    --timeout 300 \
    --max-instances 10 \
    --min-instances 1
```

---

## ⚙️ Configuración de Variables de Entorno

### Variables de Entorno Necesarias

Configura estas variables en Cloud Run:

```powershell
# Variables básicas de BD (Cloud SQL usa Unix socket, no DB_HOST)
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=<desde Secret Manager>
DB_PORT=5432
DB_USE_PROXY=false

# JWT
JWT_SECRET_KEY=<desde Secret Manager>

# Cloud Storage (opcional si usas credenciales por defecto)
GOOGLE_APPLICATION_CREDENTIALS=/secrets/google-credentials

# Document AI (opcional, si necesitas configuración específica)
DOCUMENT_AI_LOCATION=europe-west9
DOCUMENT_AI_PROCESSOR_ID=<tu-processor-id>
```

### Configurar Variables de Entorno en Cloud Run

```powershell
# Actualizar variables de entorno después del despliegue
gcloud run services update violetas-app \
    --region europe-west9 \
    --update-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false"
```

### Configurar Secretos en Cloud Run

```powershell
# Los secretos se configuran durante el despliegue con --set-secrets
# Para actualizar después:
gcloud run services update violetas-app \
    --region europe-west9 \
    --update-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest"
```

---

## 🌐 Configuración de Dominio Personalizado

### 1. Mapear Dominio a Cloud Run

```powershell
# Obtener la URL del servicio
gcloud run services describe violetas-app --region europe-west9 --format="value(status.url)"

# Mapear dominio personalizado
gcloud run domain-mappings create \
    --service violetas-app \
    --domain app.violetas.com \
    --region europe-west9
```

### 2. Configurar DNS

Cloud Run te dará registros DNS que debes agregar a tu proveedor de DNS:

```powershell
# Ver registros DNS necesarios
gcloud run domain-mappings describe \
    --domain app.violetas.com \
    --region europe-west9
```

---

## 📊 Monitoreo y Logs

### Ver Logs en Tiempo Real

```powershell
# Ver logs del servicio
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=violetas-app" --limit 50 --format json

# O desde la consola web:
# https://console.cloud.google.com/run/detail/europe-west9/violetas-app/logs
```

### Configurar Alertas

1. Ir a **Cloud Monitoring** → **Alertas**
2. Crear política de alerta para:
   - Errores 5xx
   - Latencia alta
   - Uso de memoria/CPU

---

## 🔄 Actualización de la Aplicación

### Desplegar Nueva Versión

```powershell
# Opción 1: Desde código fuente (Cloud Build automático)
gcloud run deploy violetas-app \
    --source . \
    --region europe-west9

# Opción 2: Desde imagen Docker existente
gcloud run deploy violetas-app \
    --image europe-west9-docker.pkg.dev/residencias-479706/violetas-app/violetas-app:latest \
    --region europe-west9
```

### Rollback a Versión Anterior

```powershell
# Listar revisiones
gcloud run revisions list --service violetas-app --region europe-west9

# Hacer rollback a una revisión específica
gcloud run services update-traffic violetas-app \
    --region europe-west9 \
    --to-revisions REVISION_NAME=100
```

---

## 🔧 Troubleshooting

### Problema: No se conecta a Cloud SQL

**Solución:**
1. Verificar que Cloud SQL tiene conexión Unix socket habilitada
2. Verificar que el nombre de conexión es correcto: `residencias-479706:europe-west9:residencias`
3. Verificar que `DB_USE_PROXY=false` está configurado
4. Verificar que Cloud Run tiene permisos para conectarse a Cloud SQL

```powershell
# Verificar configuración de Cloud SQL
gcloud sql instances describe residencias --format="value(settings.ipConfiguration.authorizedNetworks)"

# Verificar logs de conexión
gcloud logging read "resource.type=cloud_run_revision AND textPayload=~'database'" --limit 20
```

### Problema: Error al leer secretos

**Solución:**
1. Verificar que Secret Manager API está habilitada
2. Verificar permisos de la cuenta de servicio:

```powershell
# Ver cuenta de servicio de Cloud Run
gcloud run services describe violetas-app --region europe-west9 --format="value(spec.template.spec.serviceAccountName)"

# Dar permisos manualmente
gcloud secrets add-iam-policy-binding jwt-secret-key \
    --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

### Problema: La aplicación no inicia

**Solución:**
1. Verificar logs:

```powershell
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=violetas-app" --limit 50
```

2. Verificar que todas las variables de entorno están configuradas
3. Verificar que gunicorn está instalado en requirements.txt
4. Verificar que el puerto es correcto (Cloud Run usa PORT automáticamente)

### Problema: Timeout en requests largos

**Solución:**
Aumentar el timeout:

```powershell
gcloud run services update violetas-app \
    --region europe-west9 \
    --timeout 600
```

---

## 📝 Checklist de Despliegue

- [ ] APIs habilitadas (Cloud Run, Cloud Build, Secret Manager, Artifact Registry)
- [ ] Artifact Registry creado
- [ ] Secretos creados en Secret Manager
- [ ] Permisos configurados para Secret Manager
- [ ] Cloud SQL configurado y accesible
- [ ] Dockerfile creado y probado localmente (opcional)
- [ ] Variables de entorno documentadas
- [ ] Servicio desplegado en Cloud Run
- [ ] Conexión a Cloud SQL funcionando
- [ ] Logs accesibles y sin errores
- [ ] Dominio personalizado configurado (opcional)
- [ ] Alertas configuradas (opcional)

---

## 💰 Estimación de Costos

**Cloud Run:**
- Primeros 2 millones de requests: Gratis
- Después: $0.40 por millón de requests
- CPU/Memoria: Pago por uso (aproximadamente $0.00002400 por GB-segundo)

**Cloud SQL:**
- Depende del tamaño de la instancia (ver precios actuales)

**Cloud Storage:**
- Primeros 5 GB: Gratis
- Después: $0.020 por GB/mes

**Secret Manager:**
- Primeros 10,000 secretos: Gratis
- Después: $0.06 por secreto/mes

---

## 🔗 Enlaces Útiles

- [Documentación de Cloud Run](https://cloud.google.com/run/docs)
- [Conectar Cloud Run a Cloud SQL](https://cloud.google.com/sql/docs/postgres/connect-run)
- [Secret Manager](https://cloud.google.com/secret-manager/docs)
- [Cloud Run Pricing](https://cloud.google.com/run/pricing)

---

## 📞 Soporte

Si encuentras problemas durante el despliegue:

1. Revisar logs: `gcloud logging read ...`
2. Verificar configuración en Cloud Console
3. Consultar documentación oficial de Google Cloud
4. Revisar esta guía de troubleshooting

---

**Última actualización:** Diciembre 2024

