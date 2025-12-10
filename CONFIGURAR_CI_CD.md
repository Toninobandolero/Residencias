# 🚀 Configurar CI/CD Automático con GitHub Actions

Esta guía te ayuda a configurar GitHub Actions para que **cada vez que hagas push a `main`**, tu aplicación se despliegue automáticamente a Cloud Run.

---

## ✅ ¿Qué hace esto?

- Cada vez que haces `git push origin main` → GitHub Actions se activa
- GitHub Actions construye tu aplicación y la despliega a Cloud Run
- **Todo automático** - no necesitas ejecutar comandos manuales

---

## 📋 Paso 1: Crear Service Account y Clave

Ejecuta este script que crea todo lo necesario:

```bash
./configurar_github_actions.sh
```

**O manualmente:**

```bash
# 1. Crear Service Account
gcloud iam service-accounts create github-actions-deploy \
  --display-name="GitHub Actions Deploy" \
  --project=residencias-479706

# 2. Otorgar permisos
gcloud projects add-iam-policy-binding residencias-479706 \
  --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" \
  --role="roles/run.admin"

gcloud projects add-iam-policy-binding residencias-479706 \
  --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" \
  --role="roles/storage.admin"

gcloud projects add-iam-policy-binding residencias-479706 \
  --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"

gcloud projects add-iam-policy-binding residencias-479706 \
  --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountUser"

gcloud projects add-iam-policy-binding residencias-479706 \
  --member="serviceAccount:github-actions-deploy@residencias-479706.iam.gserviceaccount.com" \
  --role="roles/cloudsql.client"

# 3. Crear clave JSON
gcloud iam service-accounts keys create github-actions-key.json \
  --iam-account=github-actions-deploy@residencias-479706.iam.gserviceaccount.com \
  --project=residencias-479706
```

---

## 🔐 Paso 2: Añadir Secret a GitHub

### Método rápido:

1. **Ve a:** https://github.com/Toninobandolero/Residencias/settings/secrets/actions

2. **Haz clic en:** "New repository secret"

3. **Configura:**
   - **Name:** `GCP_SA_KEY`
   - **Secret:** Pega el contenido completo del archivo `github-actions-key.json`
     - Para verlo: `cat github-actions-key.json`
     - Copia TODO desde `{` hasta `}`

4. **Haz clic en:** "Add secret"

---

## ✅ Paso 3: Verificar que Funciona

### Opción 1: Hacer un cambio y push

```bash
# Hacer un cambio pequeño (ejemplo: añadir un comentario)
echo "# Test CI/CD" >> README.md

# Commit y push
git add .
git commit -m "Test: verificar CI/CD automático"
git push origin main
```

### Opción 2: Ejecutar manualmente desde GitHub

1. Ve a: https://github.com/Toninobandolero/Residencias/actions
2. Haz clic en "Deploy to Cloud Run"
3. Haz clic en "Run workflow" → "Run workflow"

---

## 📊 Ver Estado de los Despliegues

Cada vez que hagas push, puedes ver el progreso en:

**https://github.com/Toninobandolero/Residencias/actions**

Verás:
- ✅ Si el despliegue fue exitoso
- ❌ Si hubo algún error
- 📝 Logs detallados de cada paso

---

## 🎯 Flujo de Trabajo

```
1. Haces cambios en tu código
   ↓
2. git add .
   ↓
3. git commit -m "Descripción"
   ↓
4. git push origin main
   ↓
5. GitHub Actions se activa automáticamente
   ↓
6. Construye y despliega a Cloud Run
   ↓
7. Tu aplicación se actualiza en producción ✨
```

---

## 🔧 Configuración Actual

El workflow está configurado en: `.github/workflows/deploy.yml`

**Se ejecuta cuando:**
- Haces push a la rama `main`
- O lo ejecutas manualmente desde GitHub

**Lo que hace:**
1. Descarga tu código
2. Se autentica con GCP usando el secret
3. Construye la aplicación
4. Despliega a Cloud Run con todas las configuraciones
5. Verifica que funciona

---

## 🆘 Solución de Problemas

### Error: "GCP_SA_KEY not found"

**Solución:** Asegúrate de haber añadido el secret en GitHub:
- Ve a: https://github.com/Toninobandolero/Residencias/settings/secrets/actions
- Verifica que existe `GCP_SA_KEY`

### Error: "Permission denied"

**Solución:** Verifica que la Service Account tiene los permisos necesarios:
```bash
gcloud projects get-iam-policy residencias-479706 \
  --flatten="bindings[].members" \
  --filter="bindings.members:github-actions-deploy@residencias-479706.iam.gserviceaccount.com"
```

### Ver logs del workflow

1. Ve a: https://github.com/Toninobandolero/Residencias/actions
2. Haz clic en el workflow que falló
3. Expande cada paso para ver los logs detallados

---

## ✅ Checklist

- [ ] Service Account creada (`github-actions-deploy@residencias-479706.iam.gserviceaccount.com`)
- [ ] Permisos otorgados (run.admin, storage.admin, etc.)
- [ ] Clave JSON creada (`github-actions-key.json`)
- [ ] Secret `GCP_SA_KEY` añadido a GitHub
- [ ] Workflow `.github/workflows/deploy.yml` existe
- [ ] Hacer push a `main` activa el workflow
- [ ] Despliegue funciona correctamente

---

## 🎉 Listo

Una vez configurado, solo necesitas:

```bash
git add .
git commit -m "Mi cambio"
git push origin main
```

Y GitHub Actions se encargará del resto automáticamente.

---

**¿Problemas?** Revisa los logs en GitHub Actions o consulta `.github/GITHUB_ACTIONS_SETUP.md` para más detalles.
