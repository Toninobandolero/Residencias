# 🚀 Configuración de GitHub Actions para CI/CD

Esta guía te explica cómo configurar GitHub Actions para desplegar automáticamente a Cloud Run cada vez que hagas push a la rama `main`.

## 📋 Prerrequisitos

1. **Service Account en Google Cloud Platform** con los permisos necesarios
2. **Clave JSON** de la Service Account descargada
3. **Acceso de administrador** al repositorio de GitHub

---

## 🔧 Paso 1: Crear Service Account en GCP

Si ya tienes una service account configurada, puedes usarla. Si no, crea una nueva:

### Opción A: Usar Service Account existente

Si ya tienes una service account funcionando (como `621063984498-compute@developer.gserviceaccount.com`), puedes crear una nueva específica para GitHub Actions:

```powershell
# 1. Crear service account para GitHub Actions
gcloud iam service-accounts create github-actions-deploy `
    --display-name="GitHub Actions Deploy" `
    --project=residencias-479706

# 2. Otorgar permisos necesarios
gcloud projects add-iam-policy-binding residencias-479706 `
    --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" `
    --role="roles/run.admin"

gcloud projects add-iam-policy-binding residencias-479706 `
    --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" `
    --role="roles/storage.admin"

gcloud projects add-iam-policy-binding residencias-479706 `
    --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" `
    --role="roles/artifactregistry.writer"

gcloud projects add-iam-policy-binding residencias-479706 `
    --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" `
    --role="roles/iam.serviceAccountUser"

# 3. Otorgar acceso a Cloud SQL
gcloud projects add-iam-policy-binding residencias-479706 `
    --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" `
    --role="roles/cloudsql.client"
```

### Opción B: Usar Service Account existente (más simple)

Si quieres usar la service account que ya funciona (`621063984498-compute@developer.gserviceaccount.com`), solo necesitas asegurarte de que tenga los permisos necesarios.

---

## 🔑 Paso 2: Crear Clave JSON

```powershell
# Crear y descargar clave JSON
gcloud iam service-accounts keys create github-actions-key.json `
    --iam-account=github-actions-deploy@residencias-479706.iam.gserviceaccount.com `
    --project=residencias-479706

# O si usas la service account existente:
gcloud iam service-accounts keys create github-actions-key.json `
    --iam-account=621063984498-compute@developer.gserviceaccount.com `
    --project=residencias-479706
```

**⚠️ IMPORTANTE:** Este archivo contiene credenciales sensibles. No lo subas al repositorio.

---

## 🔐 Paso 3: Añadir Secret a GitHub

1. **Ve a tu repositorio en GitHub:**
   - https://github.com/Toninobandolero/Residencias

2. **Ve a Settings → Secrets and variables → Actions**

3. **Haz clic en "New repository secret"**

4. **Añade el secret `GCP_SA_KEY`:**
   - **Name:** `GCP_SA_KEY`
   - **Secret:** Pega el contenido completo del archivo `github-actions-key.json`
     - Puedes leer el archivo con: `cat github-actions-key.json` o abrirlo en un editor de texto
     - Copia TODO el contenido (incluyendo `{`, `}`, comillas, etc.)

5. **Haz clic en "Add secret"**

---

## ✅ Paso 4: Verificar Configuración

### Verificar que el secret existe

1. Ve a: `https://github.com/Toninobandolero/Residencias/settings/secrets/actions`
2. Deberías ver `GCP_SA_KEY` en la lista

### Probar el workflow

1. **Opción 1: Hacer push a main**
   ```bash
   git add .
   git commit -m "Test GitHub Actions"
   git push origin main
   ```

2. **Opción 2: Ejecutar manualmente**
   - Ve a: `https://github.com/Toninobandolero/Residencias/actions`
   - Haz clic en "Deploy to Cloud Run"
   - Haz clic en "Run workflow" → "Run workflow"

3. **Ver el progreso:**
   - Ve a la pestaña "Actions" en GitHub
   - Haz clic en el workflow que se está ejecutando
   - Verás los logs en tiempo real

---

## 📝 Variables y Secrets que usa el Workflow

### Secrets (requeridos)
- `GCP_SA_KEY`: Clave JSON de la Service Account con permisos de despliegue

### Variables de entorno (ya configuradas en el workflow)
- `PROJECT_ID`: `residencias-479706`
- `REGION`: `europe-west9`
- `SERVICE`: `violetas-app`

### Secrets de Cloud Run (ya configurados en Cloud Run, no en GitHub)
Los siguientes secrets se usan en Cloud Run pero **NO** necesitas añadirlos a GitHub:
- `JWT_SECRET_KEY` → viene de Secret Manager (`jwt-secret-key`)
- `DB_PASSWORD` → viene de Secret Manager (`db-password`)

---

## 🔍 Troubleshooting

### Error: "Permission denied" o "Forbidden"

**Causa:** La Service Account no tiene los permisos necesarios.

**Solución:**
```powershell
# Verificar permisos de la service account
gcloud projects get-iam-policy residencias-479706 \
    --flatten="bindings[].members" \
    --filter="bindings.members:github-actions-deploy@residencias-479706.iam.gserviceaccount.com"

# Añadir permisos faltantes (ejemplo)
gcloud projects add-iam-policy-binding residencias-479706 \
    --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" \
    --role="roles/run.admin"
```

### Error: "Secret not found" en Cloud Run

**Causa:** Los secrets `jwt-secret-key` o `db-password` no existen en Secret Manager.

**Solución:**
```powershell
# Verificar que existen
gcloud secrets list --project=residencias-479706

# Si no existen, crearlos
echo -n "tu-jwt-secret-key" | gcloud secrets create jwt-secret-key \
    --data-file=- \
    --project=residencias-479706

echo -n "tu-db-password" | gcloud secrets create db-password \
    --data-file=- \
    --project=residencias-479706
```

### Error: "Artifact Registry permission denied"

**Causa:** La Service Account no tiene permisos para escribir en Artifact Registry.

**Solución:**
```powershell
gcloud projects add-iam-policy-binding residencias-479706 \
    --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" \
    --role="roles/artifactregistry.writer"
```

### Ver logs del workflow

Si el workflow falla:
1. Ve a: `https://github.com/Toninobandolero/Residencias/actions`
2. Haz clic en el workflow fallido
3. Expande cada paso para ver los logs detallados

---

## 🔒 Seguridad

### Buenas prácticas

1. **No subas el archivo JSON al repositorio**
   - Añádelo a `.gitignore`: `echo "github-actions-key.json" >> .gitignore`

2. **Rota las claves periódicamente**
   ```powershell
   # Crear nueva clave
   gcloud iam service-accounts keys create new-key.json \
       --iam-account=github-actions-deploy@residencias-479706.iam.gserviceaccount.com
   
   # Actualizar secret en GitHub
   # Eliminar clave antigua
   gcloud iam service-accounts keys delete KEY_ID \
       --iam-account=github-actions-deploy@residencias-479706.iam.gserviceaccount.com
   ```

3. **Usa el principio de mínimo privilegio**
   - Solo otorga los permisos necesarios a la Service Account

---

## 📚 Recursos Adicionales

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Google Cloud Run Deployment](https://cloud.google.com/run/docs/deploying)
- [Service Accounts Best Practices](https://cloud.google.com/iam/docs/best-practices-service-accounts)

---

## ✅ Checklist de Configuración

- [ ] Service Account creada con permisos necesarios
- [ ] Clave JSON descargada
- [ ] Secret `GCP_SA_KEY` añadido a GitHub
- [ ] Workflow ejecutado exitosamente al menos una vez
- [ ] Verificado que el despliegue funciona correctamente
- [ ] Archivo JSON añadido a `.gitignore`

---

**¿Necesitas ayuda?** Revisa los logs del workflow en GitHub Actions o consulta `GUIA_TROUBLESHOOTING.md`.
