# Resumen Completo del Debugging - Container Import Failed

## Problema

Cloud Run despliega exitosamente pero el contenedor falla con "Container import failed:" (mensaje vacío)

## Lo que funciona

- ✅ **Código funciona localmente** - `python -c "import app"` funciona
- ✅ **Build es exitoso** - La imagen se construye correctamente
- ✅ **Sintaxis de Python correcta** - No hay errores de compilación
- ✅ **Secrets existen** - `jwt-secret-key` y `db-password` creados
- ✅ **Variables de entorno configuradas** - Todas las variables necesarias están en Cloud Run

## Permisos IAM Otorgados

1. ✅ **Secret Manager** - `roles/secretmanager.secretAccessor` (ambos secrets)
2. ✅ **Cloud SQL** - `roles/cloudsql.client`
3. ✅ **Cloud Storage** - `roles/storage.objectAdmin`
4. ✅ **Artifact Registry** - `roles/artifactregistry.reader` (recién añadido)
5. ✅ **Editor** - El service account también tiene rol de editor

**Service Account:** `621063984498-compute@developer.gserviceaccount.com`

## Lo que NO funciona

- ❌ **El contenedor no inicia** - Falla antes de escribir cualquier log
- ❌ **No hay logs de runtime** - El contenedor nunca llega a ejecutar Python
- ❌ **Health check falla** - El servicio nunca responde

## Intentos realizados

### 1. Con Buildpacks (intentos 1-17)
- Procfile con diferentes sintaxis
- `web: gunicorn app:app --bind 0.0.0.0:$PORT`
- `web: gunicorn app:app --bind 0.0.0.0:${PORT}`
- `web: gunicorn app:app --bind 0.0.0.0:${PORT:-8080}`
- Script bash `start.sh` con verificaciones

**Resultado:** Todos fallaron con "Container import failed"

### 2. Con Dockerfile (intentos 18-20)
- Dockerfile basado en `python:3.11-slim`
- Diferentes sintaxis de bind:
  - `--bind 0.0.0.0:$PORT`
  - `--bind :$PORT`
  - `--bind 0.0.0.0:${PORT}`

**Resultado:** Todos fallaron con "Container import failed"

### 3. Configuraciones probadas
- Con y sin `--threads`
- Con y sin `--workers`
- Con y sin `--timeout`
- Log levels: info, debug
- Puerto fijo 8080 vs variable $PORT

**Resultado:** Ninguna configuración funcionó

## Estado actual del Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD exec gunicorn app:app --bind :$PORT --workers 1 --timeout 0 --log-level debug
```

## Posibles causas restantes

### 1. Problema con $PORT
- Cloud Run podría no estar expandiendo la variable $PORT correctamente
- Solución: Usar puerto fijo 8080

### 2. Problema con gunicorn
- Gunicorn podría no encontrar `app:app`
- Solución: Probar con `python -m gunicorn` o Flask directamente

### 3. Problema con el inicio del contenedor
- El entrypoint o CMD podría tener un formato incorrecto
- Solución: Usar formato array en lugar de shell form

### 4. Problema con dependencias
- Alguna dependencia podría estar fallando al cargar
- Solución: Verificar requirements.txt o probar imagen mínima

### 5. Problema con permisos del filesystem
- Cloud Run podría tener restricciones de permisos
- Solución: Verificar que no se necesiten permisos especiales

## Próximos pasos recomendados

### Opción 1: Dockerfile con puerto fijo

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080", "--workers", "1", "--timeout", "0"]
```

### Opción 2: Usar Flask directamente (para debug)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "app.py"]
```

Y modificar app.py para que use el PORT:

```python
if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
```

### Opción 3: Imagen mínima de prueba

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN pip install flask gunicorn
RUN echo 'from flask import Flask\napp = Flask(__name__)\n@app.route("/")\ndef hello(): return "Hello"\nif __name__ == "__main__": app.run(host="0.0.0.0", port=8080)' > test.py
CMD ["python", "test.py"]
```

## Comando de despliegue actual

```powershell
gcloud run deploy violetas-app --source . --region europe-west9 --platform managed --allow-unauthenticated --add-cloudsql-instances residencias-479706:europe-west9:residencias --set-env-vars "DB_NAME=postgres,DB_USER=postgres,DB_PORT=5432,DB_USE_PROXY=false,CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias,GCS_BUCKET_NAME=violetas-documentos" --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest,DB_PASSWORD=db-password:latest" --memory 2Gi --cpu 2 --timeout 300 --max-instances 10 --min-instances 0 --project=residencias-479706 --clear-base-image
```

## Información de contacto y soporte

- Logs: https://console.cloud.google.com/logs?project=residencias-479706
- Cloud Run: https://console.cloud.google.com/run?project=residencias-479706
- Artifact Registry: https://console.cloud.google.com/artifacts?project=residencias-479706

## Notas finales

Este es un caso extremadamente frustrante porque:
- El código funciona perfectamente en local
- El build es exitoso
- Todos los permisos están otorgados
- No hay logs que indiquen qué está fallando
- El error "Container import failed" es genérico sin detalles

La única forma de avanzar es probar configuraciones más simples y construir desde cero.

