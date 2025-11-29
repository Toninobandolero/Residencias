# Configuración de Google Cloud Storage para Documentos

## Paso 1: Crear el Bucket en Cloud Storage

### Opción A: Desde la Consola Web de GCP

1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Navega a **Cloud Storage** > **Buckets**
3. Click en **"CREATE BUCKET"**
4. Configuración:
   - **Name**: `violetas-documentos` (debe ser único globalmente)
   - **Location type**: Region
   - **Location**: `europe-west9` (misma región que tu Cloud SQL)
   - **Storage class**: Standard
   - **Access control**: Uniform
   - **Protection tools**: Opcional (puedes activar versionado)

### Opción B: Desde la línea de comandos

```bash
# Instalar Google Cloud SDK si no lo tienes
# https://cloud.google.com/sdk/docs/install

# Autenticarse
gcloud auth login

# Crear el bucket
gsutil mb -p tu-proyecto-id -l europe-west9 gs://violetas-documentos
```

## Paso 2: Configurar Permisos IAM

1. En Cloud Console, ve a **IAM & Admin** > **IAM**
2. Busca la cuenta de servicio de Cloud Run (si usas Cloud Run)
3. O crea una nueva cuenta de servicio:
   - **IAM & Admin** > **Service Accounts** > **CREATE SERVICE ACCOUNT**
   - Nombre: `violetas-storage`
   - Rol: `Storage Object Admin` (para leer/escribir)
   - Descargar la clave JSON

## Paso 3: Instalar Dependencias

```bash
pip install google-cloud-storage
```

## Paso 4: Configurar Variables de Entorno

Agregar a `.env`:
```env
GCS_BUCKET_NAME=violetas-documentos
GCS_PROJECT_ID=tu-proyecto-id
GOOGLE_APPLICATION_CREDENTIALS=ruta/a/service-account-key.json
```

## Paso 5: Estructura de Carpetas en el Bucket

```
gs://violetas-documentos/
  ├── residencia-1/
  │   ├── residente-123/
  │   │   ├── medica-20250101-001.pdf
  │   │   ├── bancaria-20250101-002.pdf
  │   │   └── ...
  │   └── residente-124/
  │       └── ...
  └── residencia-2/
      └── ...
```

## Costos Estimados

- **Almacenamiento**: ~$0.020 por GB/mes
- **Operaciones**: ~$0.05 por 10,000 operaciones
- **Transferencia**: Primeros 1GB/mes gratis

**Para 2 residencias pequeñas: ~$2-5/mes**

## Seguridad

- Los archivos estarán privados por defecto
- Solo accesibles mediante autenticación
- Podemos generar URLs firmadas temporales para descargas

