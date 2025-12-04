# 🚀 Inicio Rápido - Despliegue a Producción

## Paso 1: Instalar Google Cloud SDK

### Windows

**Opción A: Usando instalador (Recomendado)**
1. Descarga el instalador desde: https://cloud.google.com/sdk/docs/install
2. Ejecuta el instalador y sigue las instrucciones
3. Reinicia PowerShell después de la instalación

**Opción B: Usando Chocolatey**
```powershell
choco install gcloudsdk
```

### Verificar instalación
```powershell
gcloud --version
```

---

## Paso 2: Autenticarse en Google Cloud

```powershell
gcloud auth login
gcloud config set project residencias-479706
```

---

## Paso 3: Habilitar APIs Necesarias

```powershell
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable artifactregistry.googleapis.com
```

---

## Paso 4: Crear Secretos en Secret Manager

### Crear secreto para JWT_SECRET_KEY
```powershell
# Genera una clave segura (o usa una existente)
$jwtSecret = "TU_CLAVE_JWT_MUY_SEGURA_AQUI_MINIMO_32_CARACTERES"

# Crear el secreto
echo -n $jwtSecret | gcloud secrets create jwt-secret-key --data-file=-
```

### Crear secreto para contraseña de BD
```powershell
# Usa la contraseña de tu base de datos Cloud SQL
$dbPassword = "TU_CONTRASEÑA_BD"

# Crear el secreto
echo -n $dbPassword | gcloud secrets create db-password --data-file=-
```

---

## Paso 5: Crear Artifact Registry (Repositorio Docker)

```powershell
gcloud artifacts repositories create violetas-app `
    --repository-format=docker `
    --location=europe-west9 `
    --description="Repositorio de imágenes Docker para Violetas App"
```

---

## Paso 6: Desplegar la Aplicación

### Opción A: Usar script automatizado (Recomendado)
```powershell
.\deploy.ps1
```

### Opción B: Comando manual
```powershell
gcloud run deploy violetas-app `
    --source . `
    --region europe-west9 `
    --platform managed `
    --allow-unauthenticated `
    --add-cloudsql-instances residencias-479706:europe-west9:residencias `
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias" `
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" `
    --memory 1Gi `
    --cpu 1 `
    --timeout 300 `
    --max-instances 10 `
    --min-instances 1
```

---

## Paso 7: Obtener URL de la Aplicación

Después del despliegue, obtendrás una URL como:
```
https://violetas-app-xxxxx-ew.a.run.app
```

Guarda esta URL para acceder a tu aplicación en producción.

---

## ✅ Verificación Post-Despliegue

1. **Probar la aplicación:**
   - Abre la URL en tu navegador
   - Intenta hacer login

2. **Ver logs:**
```powershell
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=violetas-app" --limit 50
```

3. **Ver información del servicio:**
```powershell
gcloud run services describe violetas-app --region europe-west9
```

---

## 🔧 Troubleshooting

### Error: "gcloud no se reconoce"
- Reinicia PowerShell después de instalar Google Cloud SDK
- Verifica que esté en el PATH: `$env:PATH`

### Error: "Permission denied"
- Verifica que tengas permisos de administrador en el proyecto GCP
- Ejecuta: `gcloud projects get-iam-policy residencias-479706`

### Error: "Secret not found"
- Verifica que los secretos existan: `gcloud secrets list`
- Crea los secretos faltantes (ver Paso 4)

### Error: "Cloud SQL connection failed"
- Verifica que Cloud SQL esté configurado correctamente
- Verifica que la instancia esté activa: `gcloud sql instances list`

---

## 📚 Documentación Completa

Para más detalles, consulta: `GUIA_DESPLIEGUE_PRODUCCION.md`

