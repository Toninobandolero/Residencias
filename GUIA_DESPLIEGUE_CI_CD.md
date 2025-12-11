# 🚀 Guía de Despliegue y CI/CD

**Sistema de Gestión de Residencias Violetas - Despliegue a Producción**

Guía completa para desplegar el sistema a Google Cloud Run con CI/CD automático mediante GitHub Actions.

---

## 📋 Tabla de Contenidos

1. [Requisitos Previos](#1-requisitos-previos)
2. [Despliegue Manual a Cloud Run](#2-despliegue-manual-a-cloud-run)
3. [Configuración de GitHub Actions (CI/CD)](#3-configuración-de-github-actions-cicd)
4. [Estado Actual de Producción](#4-estado-actual-de-producción)
5. [Comandos Útiles](#5-comandos-útiles)
6. [Troubleshooting de Despliegue](#6-troubleshooting-de-despliegue)

---

## 1. Requisitos Previos

### 1.1. Herramientas Necesarias

- ✅ **gcloud CLI** instalado y configurado
- ✅ **Git** configurado
- ✅ **Cuenta de GitHub** con repositorio
- ✅ **Proyecto de GCP** activo
- ✅ **Cloud SQL** configurado
- ✅ **Secret Manager** con secrets configurados

### 1.2. Permisos IAM Necesarios

**Tu usuario debe tener:**
- `roles/run.admin` - Administrar Cloud Run
- `roles/iam.serviceAccountUser` - Usar service accounts
- `roles/cloudbuild.builds.builder` - Construir imágenes
- `roles/secretmanager.secretAccessor` - Acceder a secrets

**Service Account de Cloud Run:**
```
PROJECT_NUMBER-compute@developer.gserviceaccount.com
```

**Debe tener:**
- `roles/cloudsql.client` - Conectar a Cloud SQL
- `roles/secretmanager.secretAccessor` - Leer secrets
- `roles/storage.objectAdmin` - Acceso a Storage

### 1.3. Secrets Configurados

**Secrets requeridos en Secret Manager:**

| Nombre | Descripción | Ejemplo |
|--------|-------------|---------|
| `DB_PASSWORD` | Contraseña de Cloud SQL | `password123` |
| `JWT_SECRET_KEY` | Clave para firmar JWT | `clave-super-secreta` |
| `SUPER_ADMIN_PASSWORD` | Contraseña admin inicial | `AdminPass123!` |

**Crear secrets:**
```bash
# DB Password
echo -n "tu-password" | gcloud secrets create DB_PASSWORD --data-file=-

# JWT Secret
echo -n "tu-jwt-secret" | gcloud secrets create JWT_SECRET_KEY --data-file=-

# Admin Password  
echo -n "tu-admin-pass" | gcloud secrets create SUPER_ADMIN_PASSWORD --data-file=-

# Dar acceso a Cloud Run
gcloud secrets add-iam-policy-binding DB_PASSWORD \
    --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

---

## 2. Despliegue Manual a Cloud Run

### 2.1. Preparar Dockerfile

**Dockerfile optimizado:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY . .

# Exponer puerto
EXPOSE 8080

# Comando de inicio
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
```

### 2.2. Desplegar

```bash
# 1. Autenticarse
gcloud auth login
gcloud config set project tu-proyecto-id

# 2. Deploy
gcloud run deploy violetas-app \
    --source . \
    --region=europe-west9 \
    --platform=managed \
    --allow-unauthenticated \
    --set-env-vars="DB_NAME=postgres,DB_USER=postgres,DB_HOST=/cloudsql/tu-proyecto:europe-west9:residencias,DB_PORT=5432,DB_USE_PROXY=false,GCS_BUCKET_NAME=violetas-documentos,GCS_PROJECT_ID=tu-proyecto" \
    --set-secrets="DB_PASSWORD=DB_PASSWORD:latest,JWT_SECRET_KEY=JWT_SECRET_KEY:latest,SUPER_ADMIN_PASSWORD=SUPER_ADMIN_PASSWORD:latest" \
    --add-cloudsql-instances=tu-proyecto:europe-west9:residencias \
    --memory=512Mi \
    --cpu=1 \
    --timeout=300 \
    --concurrency=80 \
    --min-instances=0 \
    --max-instances=10
```

### 2.3. Verificar Despliegue

```bash
# Ver servicio
gcloud run services describe violetas-app --region=europe-west9

# Ver URL
gcloud run services describe violetas-app --region=europe-west9 --format='value(status.url)'

# Ver logs
gcloud run services logs read violetas-app --region=europe-west9 --limit=50
```

---

## 3. Configuración de GitHub Actions (CI/CD)

### 3.1. Crear Service Account para GitHub

```bash
# 1. Crear service account
gcloud iam service-accounts create github-actions \
    --display-name="GitHub Actions Deployer"

# 2. Dar permisos
PROJECT_ID=$(gcloud config get-value project)
SA_EMAIL="github-actions@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/run.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/iam.serviceAccountUser"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/storage.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/artifactregistry.admin"

# 3. Crear key JSON
gcloud iam service-accounts keys create github-actions-key.json \
    --iam-account=$SA_EMAIL
```

### 3.2. Configurar Secrets en GitHub

**Ir a GitHub:** `Settings > Secrets and variables > Actions`

**Crear estos secrets:**

| Nombre | Valor | Origen |
|--------|-------|--------|
| `GCP_PROJECT_ID` | `tu-proyecto-id` | GCP Console |
| `GCP_SA_KEY` | `{contenido de github-actions-key.json}` | Archivo JSON |

### 3.3. Crear Workflow de GitHub Actions

**Archivo:** `.github/workflows/deploy.yml`

```yaml
name: Deploy to Cloud Run

on:
  push:
    branches: [ main ]
  workflow_dispatch:

env:
  PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}
  SERVICE_NAME: violetas-app
  REGION: europe-west9

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      id-token: write

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Authenticate to Google Cloud
      uses: google-github-actions/auth@v2
      with:
        credentials_json: ${{ secrets.GCP_SA_KEY }}

    - name: Set up Cloud SDK
      uses: google-github-actions/setup-gcloud@v2

    - name: Configure Docker to use gcloud
      run: gcloud auth configure-docker

    - name: Deploy to Cloud Run
      run: |
        gcloud run deploy $SERVICE_NAME \
          --source . \
          --region=$REGION \
          --platform=managed \
          --allow-unauthenticated \
          --set-env-vars="DB_NAME=postgres,DB_USER=postgres,DB_HOST=/cloudsql/$PROJECT_ID:$REGION:residencias,DB_PORT=5432,DB_USE_PROXY=false,GCS_BUCKET_NAME=violetas-documentos,GCS_PROJECT_ID=$PROJECT_ID" \
          --set-secrets="DB_PASSWORD=DB_PASSWORD:latest,JWT_SECRET_KEY=JWT_SECRET_KEY:latest,SUPER_ADMIN_PASSWORD=SUPER_ADMIN_PASSWORD:latest" \
          --add-cloudsql-instances=$PROJECT_ID:$REGION:residencias \
          --memory=512Mi \
          --cpu=1 \
          --timeout=300 \
          --concurrency=80 \
          --min-instances=0 \
          --max-instances=10

    - name: Show Service URL
      run: gcloud run services describe $SERVICE_NAME --region=$REGION --format='value(status.url)'
```

### 3.4. Trigger Automático

Ahora cada `git push` a `main` desplegará automáticamente:

```bash
git add .
git commit -m "Deploy to production"
git push origin main
```

**Ver progreso:** `Actions` tab en GitHub

---

## 4. Estado Actual de Producción

### 4.1. Información del Servicio

**Nombre:** `violetas-app`
**Región:** `europe-west9` (Paris)
**URL:** `https://violetas-app-HASH-ew.a.run.app`
**Plataforma:** Cloud Run (Serverless)

### 4.2. Configuración Actual

**Recursos:**
- **CPU:** 1 vCPU
- **Memoria:** 512 MB
- **Timeout:** 300 segundos (5 minutos)
- **Concurrencia:** 80 requests/instancia

**Escalado:**
- **Mínimo:** 0 instancias (escala a 0 cuando no hay tráfico)
- **Máximo:** 10 instancias

**Conexiones:**
- **Cloud SQL:** Unix socket (`/cloudsql/...`)
- **Storage:** `gs://violetas-documentos/`
- **Secrets:** Secret Manager

### 4.3. URLs Importantes

```bash
# Servicio principal
https://violetas-app-HASH-ew.a.run.app

# API
https://violetas-app-HASH-ew.a.run.app/api/v1/...

# Health check
https://violetas-app-HASH-ew.a.run.app/health
```

### 4.4. Costos Estimados

**Cloud Run (con escala a 0):**
- Request: $0.40 por millón
- CPU: $0.00002400 por vCPU-segundo
- Memoria: $0.00000250 por GiB-segundo
- **Estimado mensual:** $5-20 USD

**Cloud SQL:**
- Instancia db-f1-micro: ~$7 USD/mes
- Storage: $0.17/GB/mes
- **Estimado mensual:** $10-15 USD

**Storage:**
- $0.02/GB/mes
- **Estimado mensual:** $1-5 USD

**Total estimado:** $15-40 USD/mes

---

## 5. Comandos Útiles

### 5.1. Gestión del Servicio

```bash
# Ver estado
gcloud run services describe violetas-app --region=europe-west9

# Ver revisiones
gcloud run revisions list --service=violetas-app --region=europe-west9

# Rollback a revisión anterior
gcloud run services update-traffic violetas-app \
    --to-revisions=REVISION_NAME=100 \
    --region=europe-west9

# Ver métricas
gcloud run services describe violetas-app \
    --region=europe-west9 \
    --format="value(status.traffic)"
```

### 5.2. Logs y Debugging

```bash
# Ver logs en tiempo real
gcloud run services logs tail violetas-app --region=europe-west9

# Ver logs recientes
gcloud run services logs read violetas-app --region=europe-west9 --limit=100

# Filtrar logs de error
gcloud run services logs read violetas-app \
    --region=europe-west9 \
    --filter="severity=ERROR" \
    --limit=50

# Exportar logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=violetas-app" \
    --limit=1000 \
    --format=json > logs.json
```

### 5.3. Variables de Entorno

```bash
# Ver variables actuales
gcloud run services describe violetas-app \
    --region=europe-west9 \
    --format="value(spec.template.spec.containers[0].env)"

# Actualizar variable
gcloud run services update violetas-app \
    --region=europe-west9 \
    --update-env-vars="NEW_VAR=value"

# Eliminar variable
gcloud run services update violetas-app \
    --region=europe-west9 \
    --remove-env-vars="VAR_NAME"
```

### 5.4. Secrets

```bash
# Ver secrets del servicio
gcloud run services describe violetas-app \
    --region=europe-west9 \
    --format="value(spec.template.spec.containers[0].env)"

# Actualizar secret
gcloud run services update violetas-app \
    --region=europe-west9 \
    --update-secrets="DB_PASSWORD=DB_PASSWORD:latest"
```

---

## 6. Troubleshooting de Despliegue

### 6.1. Error: "Container failed to start"

**Causa:** Problema en el código o dependencias

**Solución:**
```bash
# 1. Ver logs de build
gcloud builds list --limit=5

# 2. Ver logs detallados del último build
LAST_BUILD=$(gcloud builds list --limit=1 --format='value(id)')
gcloud builds log $LAST_BUILD

# 3. Verificar Dockerfile
# Asegurarse de que CMD está correcto
```

### 6.2. Error: "Permission denied"

**Causa:** Service account sin permisos

**Solución:**
```bash
# Dar permisos al service account de Cloud Run
PROJECT_NUMBER=$(gcloud projects describe $(gcloud config get-value project) --format='value(projectNumber)')

gcloud projects add-iam-policy-binding $(gcloud config get-value project) \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/cloudsql.client"
```

### 6.3. Error: "Could not connect to Cloud SQL"

**Causa:** Configuración incorrecta de conexión

**Solución:**
```bash
# Verificar que la instancia está agregada
gcloud run services describe violetas-app \
    --region=europe-west9 \
    --format="value(spec.template.spec.containers[0].env)"

# Debe incluir Cloud SQL instance
# Si no, actualizar:
gcloud run services update violetas-app \
    --region=europe-west9 \
    --add-cloudsql-instances=PROJECT:REGION:INSTANCE
```

### 6.4. Error: "Secret not found"

**Causa:** Secret no existe o sin permisos

**Solución:**
```bash
# 1. Verificar que el secret existe
gcloud secrets list

# 2. Dar permisos
gcloud secrets add-iam-policy-binding SECRET_NAME \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

# 3. Actualizar servicio
gcloud run services update violetas-app \
    --region=europe-west9 \
    --update-secrets="SECRET_NAME=SECRET_NAME:latest"
```

### 6.5. Error: "Deployment timeout"

**Causa:** Build o startup tarda mucho

**Solución:**
```bash
# Aumentar timeout
gcloud run services update violetas-app \
    --region=europe-west9 \
    --timeout=600  # 10 minutos
```

---

## 7. Best Practices

### 7.1. Desarrollo y Producción

**Usar ramas separadas:**
- `develop` → Entorno de staging
- `main` → Producción

**Workflow con staging:**
```yaml
on:
  push:
    branches: [ develop ]

env:
  SERVICE_NAME: violetas-app-staging
```

### 7.2. Versionado

**Usar tags de Git:**
```bash
git tag -a v1.0.0 -m "Release 1.0.0"
git push origin v1.0.0
```

**Deploy específico:**
```bash
git checkout v1.0.0
gcloud run deploy...
```

### 7.3. Monitoreo

**Configurar alertas en GCP:**
1. Cloud Console → Monitoring
2. Alerting → Create Policy
3. Condiciones:
   - Error rate > 5%
   - Latency > 2s
   - CPU > 80%

### 7.4. Backups Automáticos

**Cloud SQL backup:**
```bash
# Ver backups
gcloud sql backups list --instance=residencias

# Crear backup manual
gcloud sql backups create --instance=residencias

# Configurar automático (ya debería estar)
gcloud sql instances patch residencias \
    --backup-start-time=03:00
```

---

## 📞 Soporte

**Documentación relacionada:**
- [GUIA_COMPLETA.md](GUIA_COMPLETA.md) - Instalación local
- [GUIA_TROUBLESHOOTING.md](GUIA_TROUBLESHOOTING.md) - Solución de problemas
- [README.md](README.md) - Visión general

**Google Cloud Documentation:**
- [Cloud Run](https://cloud.google.com/run/docs)
- [GitHub Actions](https://docs.github.com/en/actions)

**Última actualización:** Diciembre 2025
**Versión:** 2.0
