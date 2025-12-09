# Configuración de Document AI

## Variables necesarias en `.env`

Agrega estas líneas a tu archivo `.env`:

```env
# Document AI Configuration
GOOGLE_CLOUD_PROJECT_ID=621063984498
DOCUMENT_AI_LOCATION=us
DOCUMENT_AI_PROCESSOR_ID=2c78a8ebfc7ec7ae
```

## Verificar configuración

1. **Verificar que el procesador existe:**
   - Ve a: https://console.cloud.google.com/ai/document-ai/processors
   - Busca el procesador con ID: `2c78a8ebfc7ec7ae`
   - Verifica la región (Location) donde está

2. **Si el procesador no existe:**
   - Crea un nuevo procesador en la consola
   - Tipo recomendado: "Invoice Parser" o "Form Parser"
   - Selecciona la región (us, eu, o asia)
   - Copia el nuevo PROCESSOR_ID

3. **Actualizar permisos:**
   - Asegúrate de que la cuenta de servicio tenga el rol "Document AI API User"
   - Ve a: https://console.cloud.google.com/iam-admin/iam
   - Busca: `residencias@residencias-479706.iam.gserviceaccount.com`
   - Agrega el rol: "Document AI API User"

## Regiones disponibles

- `us` - Estados Unidos
- `eu` - Europa
- `asia` - Asia

La región debe coincidir con donde creaste el procesador.

