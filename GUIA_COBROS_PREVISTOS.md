# Guía de Cobros Previstos Automáticos

## Descripción

El sistema puede generar automáticamente cobros previstos para todos los residentes activos que tengan un `costo_habitacion` definido. Los cobros se generan según el método de pago preferido de cada residente.

## Configuración de Residentes

Para que un residente genere cobros previstos automáticamente, debe tener:

1. **Estado activo**: `activo = true`
2. **Costo de habitación definido**: `costo_habitacion > 0`
3. **Método de pago preferido** (opcional): `metodo_pago_preferido`

### Métodos de Pago Soportados

- **transferencia** o **transfer**: Fecha prevista día 3 del mes (rango 1-5)
- **remesa**: Fecha prevista día 30 del mes
- **otros métodos** (metálico, bizum, etc.): Fecha prevista día 5 del mes (por defecto)

Si un residente no tiene `metodo_pago_preferido` definido, se usa "transferencia" por defecto.

## Endpoint de Generación

### POST `/api/v1/facturacion/cobros/generar-previstos`

Genera automáticamente cobros previstos para todos los residentes activos.

#### Autenticación
Requiere token JWT en el header:
```
Authorization: Bearer <token>
```

#### Parámetros (opcionales en el body JSON)

```json
{
  "mes": "2025-02"  // Opcional: formato YYYY-MM. Si no se proporciona, usa el mes siguiente
}
```

#### Respuesta Exitosa (201)

```json
{
  "mensaje": "Cobros previstos generados exitosamente",
  "cobros_generados": 15,
  "cobros_duplicados": 2,
  "mes_referencia": "2025-02",
  "total_residentes_procesados": 17
}
```

#### Características

- **Evita duplicados**: No genera cobros previstos si ya existe uno para el mismo residente en el mismo mes
- **Calcula fecha automáticamente**: Según el método de pago preferido del residente
- **Usa costo_habitacion**: El monto del cobro previsto es igual al `costo_habitacion` del residente

## Ejemplo de Uso

### Con cURL

```bash
# Generar cobros para el mes siguiente (por defecto)
curl -X POST http://localhost:5000/api/v1/facturacion/cobros/generar-previstos \
  -H "Authorization: Bearer TU_TOKEN_JWT" \
  -H "Content-Type: application/json"

# Generar cobros para un mes específico
curl -X POST http://localhost:5000/api/v1/facturacion/cobros/generar-previstos \
  -H "Authorization: Bearer TU_TOKEN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"mes": "2025-03"}'
```

### Con Python

```python
import requests

API_URL = "http://localhost:5000"
TOKEN = "TU_TOKEN_JWT"

# Generar para mes siguiente
response = requests.post(
    f"{API_URL}/api/v1/facturacion/cobros/generar-previstos",
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }
)

# Generar para mes específico
response = requests.post(
    f"{API_URL}/api/v1/facturacion/cobros/generar-previstos",
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    },
    json={"mes": "2025-03"}
)

resultado = response.json()
print(f"Cobros generados: {resultado['cobros_generados']}")
```

### Con JavaScript (Frontend)

```javascript
async function generarCobrosPrevistos(mes = null) {
    const token = localStorage.getItem('violetas_token');
    const url = `${API_URL}/api/v1/facturacion/cobros/generar-previstos`;
    
    const body = mes ? { mes } : {};
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert(`✅ ${data.cobros_generados} cobros previstos generados exitosamente`);
            // Recargar lista de cobros
            loadCobros();
        } else {
            alert(`❌ Error: ${data.error}`);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error de conexión');
    }
}

// Usar:
// generarCobrosPrevistos(); // Mes siguiente
// generarCobrosPrevistos('2025-03'); // Mes específico
```

## Campos del Cobro Previsto Generado

Cada cobro previsto generado incluye:

- **id_residente**: ID del residente
- **id_residencia**: ID de la residencia (automático según el token)
- **monto**: Igual al `costo_habitacion` del residente
- **fecha_prevista**: Calculada según `metodo_pago_preferido`
- **mes_pagado**: Formato `YYYY-MM`
- **concepto**: "Pago mensual habitación - [Nombre] [Apellido]"
- **metodo_pago**: Igual al `metodo_pago_preferido` del residente
- **estado**: "pendiente"
- **es_cobro_previsto**: `true`

## Flujo de Trabajo Recomendado

1. **Configurar residentes**: Asegúrate de que cada residente tenga:
   - `costo_habitacion` definido
   - `metodo_pago_preferido` configurado (opcional pero recomendado)
   - `activo = true`

2. **Generar cobros previstos**: Al inicio de cada mes (o cuando sea necesario), ejecuta el endpoint de generación

3. **Revisar y ajustar**: Los cobros previstos pueden editarse después de generados (cambiar fecha, monto, etc.)

4. **Marcar como cobrado**: Cuando se recibe el pago, actualizar el estado del cobro previsto a "cobrado" y añadir `fecha_pago`

## Notas Importantes

- Los cobros previstos no se duplican: si ya existe uno para un residente en un mes específico, no se crea otro
- La fecha prevista se calcula automáticamente, pero puede editarse manualmente después
- El monto se toma del `costo_habitacion` del residente al momento de generar
- Si cambias el `costo_habitacion` de un residente, los cobros previstos ya generados no se actualizan automáticamente

