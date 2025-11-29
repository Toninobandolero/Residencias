# Instrucciones para Configurar Google Cloud Storage

## ✅ Lo que ya está hecho

1. ✅ Tabla de documentos actualizada con campos de Cloud Storage
2. ✅ Código backend actualizado para subir/descargar archivos
3. ✅ Frontend actualizado para subir archivos reales
4. ✅ Dependencia `google-cloud-storage` agregada a requirements.txt

## 📋 Pasos para completar la configuración

### Paso 1: Crear el Bucket en Google Cloud Console

1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Navega a **Cloud Storage** > **Buckets**
3. Click en **"CREATE BUCKET"**
4. Configuración:
   - **Name**: `violetas-documentos` (debe ser único globalmente)
   - **Location type**: Region
   - **Location**: `europe-west9` (misma región que tu Cloud SQL)
   - **Storage class**: Standard
   - **Access control**: Uniform
   - **Protection tools**: Opcional

### Paso 2: Configurar Permisos IAM

**Opción A: Para Cloud Run (Producción)**
- La cuenta de servicio de Cloud Run necesita el rol `Storage Object Admin`
- Ve a: **IAM & Admin** > **IAM**
- Busca la cuenta de servicio de Cloud Run
- Agrega el rol: `Storage Object Admin`

**Opción B: Para Desarrollo Local**
1. Ve a **IAM & Admin** > **Service Accounts**
2. Crea una nueva cuenta de servicio o usa una existente
3. Asigna el rol: `Storage Object Admin`
4. Crea una clave JSON:
   - Click en la cuenta de servicio
   - Pestaña "KEYS"
   - "ADD KEY" > "Create new key" > JSON
   - Descarga el archivo JSON

### Paso 3: Configurar Variables de Entorno

Ejecuta el script de configuración:
```bash
python configurar_cloud_storage.py
```

O manualmente, agrega a tu archivo `.env`:
```env
# Google Cloud Storage
GCS_BUCKET_NAME=violetas-documentos
GOOGLE_APPLICATION_CREDENTIALS=ruta/al/archivo-credentials.json
```

**Nota**: `GOOGLE_APPLICATION_CREDENTIALS` solo es necesario para desarrollo local. En Cloud Run se usa automáticamente.

### Paso 4: Verificar la Configuración

```bash
# Verificar que el bucket existe
python -c "from storage_manager import get_storage_client; client = get_storage_client(); bucket = client.bucket('violetas-documentos'); print('✅ Bucket existe' if bucket.exists() else '❌ Bucket no existe')"
```

## 🚀 Uso

Una vez configurado:

1. **Subir documento**: 
   - Abre el detalle de un residente
   - En la sección "Documentación"
   - Selecciona tipo, archivo y descripción
   - Click en "Subir Documento"

2. **Descargar documento**:
   - Click en el botón "📥 Descargar" junto al documento
   - Se abrirá una URL firmada válida por 1 hora

3. **Eliminar documento**:
   - Click en "Eliminar"
   - Se eliminará de la base de datos y de Cloud Storage

## 🔒 Seguridad

- Los archivos son **privados** por defecto
- Solo accesibles mediante URLs firmadas temporales
- Las URLs expiran después de 1 hora
- Separación por residencia en la estructura de carpetas

## 📁 Estructura en Cloud Storage

```
gs://violetas-documentos/
  ├── residencia-1/
  │   ├── residente-123/
  │   │   ├── medica-20250101-143022.pdf
  │   │   ├── bancaria-20250101-143045.pdf
  │   │   └── ...
  │   └── residente-124/
  │       └── ...
  └── residencia-2/
      └── ...
```

## 💰 Costos Estimados

- **Almacenamiento**: ~$0.020 por GB/mes
- **Operaciones**: ~$0.05 por 10,000 operaciones
- **Transferencia**: Primeros 1GB/mes gratis

**Para 2 residencias pequeñas: ~$2-5/mes**

## ❓ Solución de Problemas

### Error: "Bucket no existe"
- Verifica que el bucket fue creado en Cloud Console
- Verifica el nombre en `.env` (`GCS_BUCKET_NAME`)

### Error: "Permission denied"
- Verifica que la cuenta de servicio tiene el rol `Storage Object Admin`
- En desarrollo local, verifica la ruta a las credenciales JSON

### Error: "No module named 'google.cloud.storage'"
```bash
pip install google-cloud-storage
```

## 📞 Soporte

Si tienes problemas, verifica:
1. Que el bucket existe en Cloud Console
2. Que las credenciales son correctas
3. Que los permisos IAM están configurados
4. Que las variables de entorno están en `.env`

