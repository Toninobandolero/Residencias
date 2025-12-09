# Solución: Container Import Failed

## 🎯 Problema

Después de 20+ intentos de despliegue, la aplicación fallaba con:
```
ERROR: Container import failed:
```

Sin ningún mensaje de error adicional ni logs de runtime.

## 🔍 Diagnóstico

El error era silencioso porque Cloud Run rechazaba la configuración **antes** de intentar ejecutar el contenedor, por lo que nunca generaba logs de runtime.

### Causas investigadas (descartadas)

1. ❌ Errores de sintaxis en código → Código funcionaba localmente
2. ❌ Dependencias faltantes → `requirements.txt` completo
3. ❌ Permisos IAM → Todos los permisos otorgados:
   - Secret Manager Secret Accessor
   - Cloud SQL Client
   - Storage Object Viewer
   - Artifact Registry Reader
4. ❌ Versión de Python → `runtime.txt` configurado correctamente
5. ❌ Comando Procfile → Simplificado múltiples veces
6. ❌ Dockerfile → Probadas múltiples configuraciones

## ✅ Solución

### La causa raíz: Variable de entorno `PORT`

Cloud Run tiene variables de entorno **reservadas** que establece automáticamente:
- `PORT` - Puerto en el que el contenedor debe escuchar (típicamente 8080)
- `K_SERVICE` - Nombre del servicio
- `K_REVISION` - Nombre de la revisión
- `K_CONFIGURATION` - Nombre de la configuración

**No se pueden sobrescribir estas variables.**

### Cambios necesarios

#### 1. Eliminar `PORT` de las variables de entorno

**❌ Incorrecto:**
```bash
gcloud run deploy violetas-app \
  --set-env-vars "PORT=8080,DB_NAME=postgres,..."
```

**✅ Correcto:**
```bash
gcloud run deploy violetas-app \
  --set-env-vars "DB_NAME=postgres,DB_USER=postgres,..."
```

#### 2. Usar `$PORT` en el Dockerfile

**❌ Incorrecto:**
```dockerfile
ENV PORT=8080
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080"]
```

**✅ Correcto:**
```dockerfile
# No establecer ENV PORT
CMD gunicorn app:app --bind 0.0.0.0:$PORT
```

**Nota:** Usar formato shell (no array) para que `$PORT` se expanda correctamente.

#### 3. Dockerfile final funcional

```dockerfile
# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py db_connector.py storage_manager.py validators.py ./
COPY static ./static

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose port (Cloud Run sets $PORT automatically)
EXPOSE 8080

# Use shell format to expand $PORT
CMD gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 0 --log-level debug
```

## 🚀 Comando de despliegue correcto

```powershell
# Construir imagen
gcloud builds submit --tag europe-west9-docker.pkg.dev/residencias-479706/cloud-run-source-deploy/violetas-app

# Desplegar
gcloud run deploy violetas-app `
    --image europe-west9-docker.pkg.dev/residencias-479706/cloud-run-source-deploy/violetas-app `
    --region europe-west9 `
    --platform managed `
    --allow-unauthenticated `
    --add-cloudsql-instances "residencias-479706:europe-west9:residencias" `
    --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias,GCS_BUCKET_NAME=violetas-documentos" `
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" `
    --memory 2Gi `
    --cpu 2 `
    --timeout 300 `
    --max-instances 10 `
    --min-instances 0 `
    --project residencias-479706
```

## 🔍 Cómo detectar este problema

Si ves "Container import failed" sin más detalles:

1. **Revisa las variables de entorno** - Asegúrate de no estar estableciendo variables reservadas
2. **Consulta la documentación oficial** de variables reservadas:
   - https://cloud.google.com/run/docs/container-contract#env-vars

## 📊 Resultado

```
✅ Build exitoso
✅ Deploy exitoso
✅ Health check OK: 200
```

**URL:** https://violetas-app-621063984498.europe-west9.run.app

## 💡 Lecciones aprendidas

1. **Variables reservadas** - Cloud Run tiene variables que NO se pueden sobrescribir
2. **Formato CMD en Dockerfile** - Usar formato shell (no array) cuando necesites expansión de variables
3. **Logs silenciosos** - Si el error ocurre antes de iniciar el contenedor, no habrá logs de runtime
4. **Mensajes de error** - "Container import failed" sin detalles suele indicar problema de configuración, no de código

## 🛠️ Script automatizado

Usa `build_and_deploy.ps1` para deployments futuros:

```powershell
.\build_and_deploy.ps1
```

Este script:
1. Construye la imagen con Cloud Build
2. Despliega a Cloud Run con configuración correcta
3. Verifica el estado del servicio
4. Ejecuta health check

---

**Fecha de resolución:** Diciembre 6, 2025  
**Tiempo total de debugging:** ~20 iteraciones  
**Causa:** Variable de entorno reservada `PORT`

