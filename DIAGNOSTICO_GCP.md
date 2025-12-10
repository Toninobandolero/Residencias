# 🔍 Diagnóstico Completo de Configuración GCP

Esta guía te ayuda a verificar toda la configuración de Google Cloud Platform para tu aplicación.

## 📋 Información del Proyecto

- **Project ID:** `residencias-479706`
- **Región:** `europe-west9`
- **Servicio Cloud Run:** `violetas-app`
- **Cloud SQL Instance:** `residencias-479706:europe-west9:residencias`
- **Service Account (por defecto):** `621063984498-compute@developer.gserviceaccount.com`

---

## 🚀 Comandos de Verificación Rápida

### 1. Verificar Autenticación

```bash
gcloud auth list
```

**Resultado esperado:** Debe mostrar al menos una cuenta activa.

**Si no estás autenticado:**
```bash
gcloud auth login
```

### 2. Verificar Proyecto Configurado

```bash
gcloud config get-value project
```

**Resultado esperado:** `residencias-479706`

**Si está en otro proyecto:**
```bash
gcloud config set project residencias-479706
```

### 3. Verificar que el Proyecto Existe

```bash
gcloud projects describe residencias-479706 --format="table(projectId,name,projectNumber)"
```

**Resultado esperado:** Información del proyecto.

---

## ☁️ Verificación de Cloud Run

### Estado del Servicio

```bash
gcloud run services describe violetas-app \
  --region europe-west9 \
  --project residencias-479706 \
  --format="table(status.url,status.latestReadyRevisionName)"
```

### Variables de Entorno Configuradas

```bash
gcloud run services describe violetas-app \
  --region europe-west9 \
  --project residencias-479706 \
  --format="yaml(spec.template.spec.containers[0].env)"
```

**Variables esperadas:**
- `DB_NAME=postgres`
- `DB_USER=postgres`
- `DB_PORT=5432`
- `DB_USE_PROXY=false`
- `CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias`
- `GCS_BUCKET_NAME=violetas-documentos`

### Secrets Configurados

```bash
gcloud run services describe violetas-app \
  --region europe-west9 \
  --project residencias-479706 \
  --format="yaml(spec.template.spec.containers[0].env)" | grep -A 5 "valueFrom"
```

**Secrets esperados:**
- `JWT_SECRET_KEY` → `jwt-secret-key:latest`
- `DB_PASSWORD` → `db-password:latest`

### Última Revisión

```bash
gcloud run revisions list \
  --service violetas-app \
  --region europe-west9 \
  --project residencias-479706 \
  --limit 5
```

### Logs Recientes

```bash
gcloud run services logs read violetas-app \
  --region europe-west9 \
  --project residencias-479706 \
  --limit 50
```

---

## 🔐 Verificación de Service Account y Permisos IAM

### Obtener Service Account del Servicio

```bash
# Método 1: Desde el servicio
gcloud run services describe violetas-app \
  --region europe-west9 \
  --project residencias-479706 \
  --format="value(spec.template.spec.serviceAccountName)"

# Método 2: Service Account por defecto
PROJECT_NUMBER=$(gcloud projects describe residencias-479706 --format="value(projectNumber)")
echo "${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
```

### Verificar Permisos IAM de la Service Account

```bash
SERVICE_ACCOUNT="621063984498-compute@developer.gserviceaccount.com"

gcloud projects get-iam-policy residencias-479706 \
  --flatten="bindings[].members" \
  --filter="bindings.members:${SERVICE_ACCOUNT}" \
  --format="table(bindings.role)"
```

### Permisos Necesarios

La Service Account necesita estos roles:

1. **`roles/secretmanager.secretAccessor`**
   - Para acceder a `jwt-secret-key` y `db-password`

2. **`roles/cloudsql.client`**
   - Para conectarse a Cloud SQL

3. **`roles/storage.objectViewer`** (opcional, si usas GCS)
   - Para leer documentos en Cloud Storage

4. **`roles/artifactregistry.reader`** (para GitHub Actions)
   - Para leer imágenes Docker

### Verificar Permisos Específicos

```bash
SERVICE_ACCOUNT="621063984498-compute@developer.gserviceaccount.com"

# Verificar Secret Manager
gcloud projects get-iam-policy residencias-479706 \
  --flatten="bindings[].members" \
  --filter="bindings.members:${SERVICE_ACCOUNT} AND bindings.role:roles/secretmanager.secretAccessor"

# Verificar Cloud SQL
gcloud projects get-iam-policy residencias-479706 \
  --flatten="bindings[].members" \
  --filter="bindings.members:${SERVICE_ACCOUNT} AND bindings.role:roles/cloudsql.client"
```

---

## 🔑 Verificación de Secrets

### Listar Todos los Secrets

```bash
gcloud secrets list --project=residencias-479706
```

### Verificar que los Secrets Existen

```bash
# Verificar jwt-secret-key
gcloud secrets describe jwt-secret-key --project=residencias-479706

# Verificar db-password
gcloud secrets describe db-password --project=residencias-479706
```

### Verificar Permisos de los Secrets

```bash
# Permisos de jwt-secret-key
gcloud secrets get-iam-policy jwt-secret-key --project=residencias-479706

# Permisos de db-password
gcloud secrets get-iam-policy db-password --project=residencias-479706
```

**Debe incluir:**
```
bindings:
- members:
  - serviceAccount:621063984498-compute@developer.gserviceaccount.com
  role: roles/secretmanager.secretAccessor
```

### Otorgar Permisos a un Secret (si faltan)

```bash
SERVICE_ACCOUNT="621063984498-compute@developer.gserviceaccount.com"

# Para jwt-secret-key
gcloud secrets add-iam-policy-binding jwt-secret-key \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor" \
  --project=residencias-479706

# Para db-password
gcloud secrets add-iam-policy-binding db-password \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor" \
  --project=residencias-479706
```

---

## 🗄️ Verificación de Cloud SQL

### Estado de la Instancia

```bash
gcloud sql instances describe residencias \
  --project=residencias-479706 \
  --format="table(name,state,databaseVersion,region)"
```

**Resultado esperado:** Estado debe ser `RUNNABLE`

### Verificar Conexión

```bash
gcloud sql instances describe residencias \
  --project=residencias-479706 \
  --format="get(connectionName)"
```

**Resultado esperado:** `residencias-479706:europe-west9:residencias`

### Verificar Autorización de Red

```bash
gcloud sql instances describe residencias \
  --project=residencias-479706 \
  --format="get(settings.ipConfiguration.authorizedNetworks)"
```

---

## 📦 Verificación de Artifact Registry (para builds)

### Listar Repositorios

```bash
gcloud artifacts repositories list \
  --project=residencias-479706 \
  --location=europe-west9
```

### Ver Imágenes Docker

```bash
gcloud artifacts docker images list \
  europe-west9-docker.pkg.dev/residencias-479706/cloud-run-source-deploy/violetas-app \
  --project=residencias-479706
```

---

## 🔧 Script de Verificación Automática

Puedes ejecutar el script PowerShell que creamos:

```powershell
.\verificar_configuracion_gcp.ps1
```

O ejecutar todos los comandos manualmente usando la lista de arriba.

---

## ✅ Checklist de Configuración

Marca cada ítem cuando lo verifiques:

### Configuración Básica
- [ ] Proyecto configurado correctamente
- [ ] Autenticación activa
- [ ] Cloud Run service existe y está activo
- [ ] Última revisión está en estado "Ready"

### Secrets
- [ ] `jwt-secret-key` existe en Secret Manager
- [ ] `db-password` existe en Secret Manager
- [ ] Service Account tiene permisos para ambos secrets

### Service Account y Permisos
- [ ] Service Account identificada
- [ ] `roles/secretmanager.secretAccessor` otorgado
- [ ] `roles/cloudsql.client` otorgado
- [ ] `roles/storage.objectViewer` otorgado (si aplica)

### Cloud SQL
- [ ] Instancia existe
- [ ] Estado es "RUNNABLE"
- [ ] Connection name correcto

### Variables de Entorno
- [ ] Todas las variables de entorno configuradas
- [ ] Secrets referenciados correctamente

---

## 🆘 Problemas Comunes y Soluciones

### Error: "Permission denied" al acceder a secrets

**Solución:**
```bash
SERVICE_ACCOUNT="621063984498-compute@developer.gserviceaccount.com"

gcloud secrets add-iam-policy-binding jwt-secret-key \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor" \
  --project=residencias-479706

gcloud secrets add-iam-policy-binding db-password \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor" \
  --project=residencias-479706
```

### Error: "Failed to connect to database"

**Verificar:**
1. Cloud SQL está en estado "RUNNABLE"
2. `CLOUD_SQL_CONNECTION_NAME` es correcto
3. Service Account tiene `roles/cloudsql.client`
4. Revisar logs de Cloud Run

### Error: "Secret not found"

**Solución:**
```bash
# Verificar que existe
gcloud secrets list --project=residencias-479706

# Si no existe, crear (ejemplo para jwt-secret-key)
echo -n "tu-jwt-secret-key-aqui" | gcloud secrets create jwt-secret-key \
  --data-file=- \
  --project=residencias-479706
```

---

## 📚 Recursos Adicionales

- **Console de Cloud Run:** https://console.cloud.google.com/run/detail/europe-west9/violetas-app?project=residencias-479706
- **Console de Secret Manager:** https://console.cloud.google.com/security/secret-manager?project=residencias-479706
- **Console de Cloud SQL:** https://console.cloud.google.com/sql/instances/residencias?project=residencias-479706
- **Console de IAM:** https://console.cloud.google.com/iam-admin/iam?project=residencias-479706

---

**¿Necesitas ayuda específica?** Ejecuta los comandos de verificación y comparte los resultados.
