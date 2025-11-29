# Guía de Almacenamiento de Documentos - Google Cloud Storage

## Situación Actual

Actualmente, el sistema guarda solo **metadatos** de los documentos en la base de datos PostgreSQL:
- Tipo de documento (Médica, Bancaria, Legal, etc.)
- Nombre del archivo
- Descripción
- Fecha de subida

**Los archivos reales NO se están guardando todavía.**

## Opciones de Almacenamiento

### 1. Google Cloud Storage (Recomendado) ⭐

**Ventajas:**
- Integración nativa con GCP (ya estás usando Cloud SQL)
- Escalable y seguro
- Acceso controlado por permisos
- Ideal para producción

**Pasos para configurar:**

1. **Crear un bucket en Cloud Storage:**
   ```bash
   # Instalar gcloud CLI si no lo tienes
   # Luego crear el bucket:
   gsutil mb -p tu-proyecto-gcp -l europe-west9 gs://violetas-documentos
   ```

2. **Configurar permisos:**
   - Dar acceso a la cuenta de servicio de Cloud Run
   - Configurar IAM para lectura/escritura

3. **Instalar dependencias en Python:**
   ```bash
   pip install google-cloud-storage
   ```

4. **Actualizar `requirements.txt`:**
   ```
   google-cloud-storage==2.10.0
   ```

5. **Modificar el código para subir archivos:**
   - Agregar endpoint para subir archivos
   - Guardar archivos en Cloud Storage
   - Guardar URL en la base de datos

### 2. Sistema de Archivos Local (Solo desarrollo)

**Ventajas:**
- Simple de implementar
- No requiere configuración adicional

**Desventajas:**
- No escalable
- Se pierde al reiniciar el servidor
- No recomendado para producción

### 3. Base de Datos (NO recomendado)

Guardar archivos como BLOB en PostgreSQL:
- Límite de tamaño
- Ralentiza la base de datos
- No es eficiente

## Recomendación: Google Cloud Storage

### Estructura propuesta:

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

### Campos adicionales en la tabla:

```sql
ALTER TABLE documento_residente 
ADD COLUMN IF NOT EXISTS url_archivo VARCHAR(500),
ADD COLUMN IF NOT EXISTS tamaño_bytes BIGINT,
ADD COLUMN IF NOT EXISTS tipo_mime VARCHAR(100);
```

## Implementación Sugerida

1. **Crear bucket en Cloud Storage** (una sola vez)
2. **Actualizar código para:**
   - Subir archivos a Cloud Storage
   - Guardar URL en la base de datos
   - Descargar archivos desde Cloud Storage
3. **Frontend:**
   - Agregar input de tipo `file` para subir archivos
   - Mostrar enlaces para descargar documentos

## Costos Aproximados

- **Cloud Storage Standard:** ~$0.020 por GB/mes
- **Operaciones:** ~$0.05 por 10,000 operaciones
- **Transferencia:** Primeros 1GB/mes gratis

Para una residencia pequeña: **~$1-5/mes**

## Próximos Pasos

1. ¿Quieres que configuremos Cloud Storage ahora?
2. ¿O prefieres empezar con almacenamiento local para desarrollo?

---

**Nota:** Por ahora, el sistema funciona guardando solo metadatos. Los archivos reales se pueden agregar después sin afectar los datos existentes.

