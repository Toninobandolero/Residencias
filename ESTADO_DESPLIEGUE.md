# Estado del Despliegue - violetas-app

## Último cambio realizado

**Fecha:** 4 de diciembre de 2025, 19:50

**Cambio:** Se creó un Dockerfile personalizado para tener más control sobre la construcción del contenedor.

## Archivos modificados

1. **Dockerfile** (nuevo) - Define cómo construir el contenedor
2. **.dockerignore** (nuevo) - Excluye archivos innecesarios
3. **app.py** - Añadidos mensajes de logging para diagnóstico:
   - `=== INICIANDO IMPORTACIÓN DE APP.PY ===`
   - `=== APP FLASK CREADA ===`
   - `=== CORS HABILITADO ===`

## Configuración actual

### Dockerfile
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD exec gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 300 --log-level info
```

### Variables de entorno configuradas
- `DB_NAME=postgres`
- `DB_USER=postgres`
- `DB_PORT=5432`
- `DB_USE_PROXY=false`
- `CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias`
- `GCS_BUCKET_NAME=violetas-documentos`

### Secrets configurados
- `JWT_SECRET_KEY` → `jwt-secret-key:latest`
- `DB_PASSWORD` → `db-password:latest`

### Permisos IAM verificados
- ✅ Secret Manager: `roles/secretmanager.secretAccessor` (ambos secrets)
- ✅ Cloud SQL: `roles/cloudsql.client`
- ✅ Cloud Storage: `roles/storage.objectAdmin`

## Cómo verificar el estado

### 1. Ver logs en consola web

**URL directa:**
```
https://console.cloud.google.com/run/detail/europe-west9/violetas-app/logs?project=residencias-479706
```

**Qué buscar:**
- Mensajes de logging añadidos (INICIANDO, APP FLASK CREADA, etc.)
- Mensajes de gunicorn (Booting worker, Listening at, etc.)
- Errores de Python o importación

### 2. Ver estado del servicio

**URL directa:**
```
https://console.cloud.google.com/run/detail/europe-west9/violetas-app?project=residencias-479706
```

**Verificar:**
- Estado de la última revisión (verde/rojo)
- Mensaje de error si hay
- URL del servicio

### 3. Probar el servicio

**URL del servicio:**
```
https://violetas-app-621063984498.europe-west9.run.app
```

**Health check:**
```
https://violetas-app-621063984498.europe-west9.run.app/health
```

## Próximos pasos

### Si el servicio funciona
1. Probar el login en `/api/v1/login`
2. Verificar que los residentes se listan correctamente
3. Listo para usar

### Si sigue fallando
1. Revisar los logs en la consola web (URL arriba)
2. Buscar mensajes de error específicos
3. Verificar que los mensajes de logging aparecen
4. Si no aparecen mensajes de logging, el contenedor falla antes de ejecutar Python

## Posibles causas si sigue fallando

1. **Problema con secrets:**
   - Los secrets no se pueden leer al iniciar
   - Solución: Verificar permisos en Secret Manager

2. **Problema con Cloud SQL:**
   - No puede conectar a la base de datos
   - Solución: Verificar que Cloud SQL Instances está configurado

3. **Problema con el puerto:**
   - La variable `$PORT` no se está expandiendo correctamente
   - Solución: Cambiar CMD en Dockerfile a usar puerto fijo 8080

4. **Problema con gunicorn:**
   - Gunicorn no puede cargar la app
   - Solución: Ver logs para mensaje de error específico

## Comando para redesplegar

```powershell
gcloud run deploy violetas-app --source . --region europe-west9 --platform managed --allow-unauthenticated --add-cloudsql-instances residencias-479706:europe-west9:residencias --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias,GCS_BUCKET_NAME=violetas-documentos" --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" --memory 2Gi --cpu 2 --timeout 300 --max-instances 10 --min-instances 0 --project=residencias-479706 --clear-base-image
```

## Comando para ver logs

```powershell
gcloud run services logs read violetas-app --region europe-west9 --project residencias-479706 --limit 50
```

## Notas adicionales

- El código funciona correctamente en local
- El build de la imagen es exitoso
- El problema está en el inicio del contenedor en Cloud Run
- Todos los permisos IAM están correctamente configurados

