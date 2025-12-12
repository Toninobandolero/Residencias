# 📦 Guía de Artículos de Factura

## 📋 Descripción

Sistema para capturar, almacenar y analizar las **líneas de detalle (artículos)** de las facturas, además de los importes totales. Esto permite un control y análisis mucho más profundo de los gastos.

---

## 🎯 Ventajas de Guardar Artículos

### 📊 **Análisis Detallado**
```
❌ ANTES (solo totales):
   "Factura Supermercado: 241,80€"
   
✅ AHORA (con detalle):
   - Verduras: 45,20€
   - Carne: 67,50€
   - Limpieza: 38,90€
   - Bebidas: 90,20€
   Total: 241,80€
```

### 💡 **Casos de Uso**

#### 1. **Estadísticas por Categoría**
- ¿Cuánto gastamos en alimentación vs limpieza?
- ¿Qué proveedor nos cobra más por productos de higiene?
- Tendencia del gasto en medicamentos por mes

#### 2. **Auditoría Detallada**
- ¿Qué compramos exactamente el 15 de marzo?
- ¿Cuántas veces pedimos pañales este mes?
- Verificar si un artículo específico se cobró correctamente

#### 3. **Reportes Avanzados**
- Top 10 productos más caros
- Evolución del precio de un producto específico
- Comparativa de precios entre proveedores

#### 4. **Control Presupuestario**
- Alerta: gasto en medicamentos superó presupuesto
- Reducir gasto en categoría "Limpieza profesional"
- Optimizar compras de artículos duplicados

#### 5. **Predicción**
- Basado en histórico, necesitarás pedir gel desinfectante pronto
- Patrón de consumo de material médico

---

## 🗄️ Estructura de Base de Datos

### Tabla: `articulo_factura`

```sql
CREATE TABLE articulo_factura (
    id                  SERIAL PRIMARY KEY,
    pago_proveedor_id   INTEGER NOT NULL,              -- FK a pago_proveedor
    
    -- Datos del artículo
    descripcion         TEXT NOT NULL,                 -- "Verduras frescas", "Gel 500ml"
    cantidad            DECIMAL(10, 2) DEFAULT 1,      -- 2.5 (kg), 3 (unidades)
    unidad              VARCHAR(20),                   -- "kg", "ud", "litros"
    
    -- Importes
    precio_unitario     DECIMAL(10, 2),                -- 15,50€ por unidad
    subtotal            DECIMAL(10, 2) NOT NULL,       -- Precio sin IVA
    iva_porcentaje      INTEGER,                       -- 4, 10, 21
    iva_importe         DECIMAL(10, 2),                -- Importe del IVA
    total               DECIMAL(10, 2) NOT NULL,       -- Total con IVA
    
    -- Categorización (futuro)
    categoria           VARCHAR(100),                  -- "Alimentación", "Limpieza"
    subcategoria        VARCHAR(100),                  -- "Verduras", "Desinfectantes"
    
    fecha_creacion      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Índices
- `idx_articulo_factura_pago` → Búsqueda rápida por pago
- `idx_articulo_factura_categoria` → Análisis por categoría
- `idx_articulo_factura_descripcion` → Búsqueda de productos

---

## 🚀 Instalación

### 1. Crear la Tabla

```bash
python ejecutar_articulos_factura_table.py
```

**Salida esperada:**
```
🔧 Conectando a la base de datos...
📊 Creando tabla articulo_factura...
✅ Tabla articulo_factura creada exitosamente

📋 Columnas de la tabla (total: 13):
   - id                        (integer)
   - pago_proveedor_id         (integer)
   - descripcion               (text)
   - cantidad                  (numeric)
   - unidad                    (character varying)
   - precio_unitario           (numeric)
   - subtotal                  (numeric)
   - iva_porcentaje            (integer)
   - iva_importe               (numeric)
   - total                     (numeric)
   - categoria                 (character varying)
   - subcategoria              (character varying)
   - fecha_creacion            (timestamp without time zone)

🔍 Índices creados (total: 4):
   - articulo_factura_pkey
   - idx_articulo_factura_pago
   - idx_articulo_factura_categoria
   - idx_articulo_factura_descripcion

✅ TABLA LISTA PARA USAR
```

### 2. Reiniciar el Servidor

```bash
python app.py
```

---

## 🔧 Funcionamiento

### 🤖 Extracción Automática con IA

Cuando procesas una factura con Document AI, el sistema:

1. **Extrae el texto OCR completo**
2. **Busca líneas de artículos** usando patrones inteligentes:
   ```
   "Verduras frescas    2.5  kg   15,50   38,75"
   "Gel desinfectante   3    ud   12,30   36,90"
   ```
3. **Valida coherencia**: `cantidad × precio ≈ total`
4. **Incluye artículos en `datos_extraidos['articulos']`**

### 📊 Patrones Detectados

```python
# Formato típico en facturas españolas:
# [descripción] [cantidad] [unidad] [precio] [total]

Ejemplos detectados:
✅ "Pañales adulto      5    cajas  12,50   62,50"
✅ "Leche desnatada     10   l      0,85    8,50"
✅ "Medicamento X       1    ud     45,30   45,30"
```

### 💾 Guardado Automático

Al crear un pago a proveedor (`POST /api/v1/facturacion/proveedores`):

```json
{
  "proveedor": "Supermercado X",
  "concepto": "Compra mensual",
  "monto": 241.80,
  "id_residencia": 1,
  "articulos": [
    {
      "descripcion": "Verduras frescas",
      "cantidad": 2.5,
      "unidad": "kg",
      "precio_unitario": 15.50,
      "total": 38.75
    },
    {
      "descripcion": "Gel desinfectante",
      "cantidad": 3,
      "unidad": "ud",
      "precio_unitario": 12.30,
      "total": 36.90
    }
  ]
}
```

El sistema:
1. ✅ Guarda el pago en `pago_proveedor`
2. ✅ Guarda cada artículo en `articulo_factura`
3. ✅ Asocia automáticamente mediante `pago_proveedor_id`

### 🔍 Consulta de Artículos

Al obtener un pago (`GET /api/v1/facturacion/proveedores/123`):

```json
{
  "id_pago": 123,
  "proveedor": "Supermercado X",
  "monto": 241.80,
  "articulos": [
    {
      "id": 1,
      "descripcion": "Verduras frescas",
      "cantidad": 2.5,
      "unidad": "kg",
      "precio_unitario": 15.50,
      "subtotal": 38.75,
      "iva_porcentaje": 4,
      "iva_importe": 1.55,
      "total": 40.30,
      "categoria": null,
      "subcategoria": null
    },
    {
      "id": 2,
      "descripcion": "Gel desinfectante",
      "cantidad": 3,
      "unidad": "ud",
      "precio_unitario": 12.30,
      "subtotal": 36.90,
      "iva_porcentaje": 21,
      "iva_importe": 7.75,
      "total": 44.65,
      "categoria": null,
      "subcategoria": null
    }
  ]
}
```

---

## 📊 Consultas Útiles

### Top 10 Artículos Más Caros (Mes Actual)

```sql
SELECT 
    a.descripcion,
    COUNT(*) as veces_comprado,
    AVG(a.precio_unitario) as precio_promedio,
    SUM(a.total) as gasto_total
FROM articulo_factura a
INNER JOIN pago_proveedor p ON a.pago_proveedor_id = p.id_pago
WHERE p.fecha_pago >= DATE_TRUNC('month', CURRENT_DATE)
GROUP BY a.descripcion
ORDER BY gasto_total DESC
LIMIT 10;
```

### Gasto por Categoría (Cuando se categorice)

```sql
SELECT 
    a.categoria,
    COUNT(*) as num_articulos,
    SUM(a.total) as gasto_total
FROM articulo_factura a
INNER JOIN pago_proveedor p ON a.pago_proveedor_id = p.id_pago
WHERE a.categoria IS NOT NULL
  AND p.id_residencia = 1
  AND p.fecha_pago >= '2024-01-01'
GROUP BY a.categoria
ORDER BY gasto_total DESC;
```

### Historial de Precio de un Producto

```sql
SELECT 
    p.fecha_pago,
    p.proveedor,
    a.cantidad,
    a.unidad,
    a.precio_unitario,
    a.total
FROM articulo_factura a
INNER JOIN pago_proveedor p ON a.pago_proveedor_id = p.id_pago
WHERE LOWER(a.descripcion) LIKE '%gel desinfectante%'
ORDER BY p.fecha_pago DESC;
```

### Comparar Precios Entre Proveedores

```sql
SELECT 
    p.proveedor,
    COUNT(DISTINCT p.id_pago) as num_facturas,
    AVG(a.precio_unitario) as precio_promedio,
    MIN(a.precio_unitario) as precio_min,
    MAX(a.precio_unitario) as precio_max
FROM articulo_factura a
INNER JOIN pago_proveedor p ON a.pago_proveedor_id = p.id_pago
WHERE LOWER(a.descripcion) LIKE '%pañales%'
GROUP BY p.proveedor
ORDER BY precio_promedio ASC;
```

---

## 🎨 Próximos Pasos (Frontend)

### 1. **Mostrar Artículos en Modal de Detalle**

```javascript
// En renderPagoProveedorDetails()
if (pago.articulos && pago.articulos.length > 0) {
    html += `
        <div style="margin-top: 20px;">
            <h4 style="color: #667eea;">📦 Artículos de la Factura</h4>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Descripción</th>
                        <th>Cantidad</th>
                        <th>Precio Unit.</th>
                        <th>Total</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    pago.articulos.forEach(art => {
        html += `
            <tr>
                <td>${art.descripcion}</td>
                <td>${art.cantidad} ${art.unidad || 'ud'}</td>
                <td>${art.precio_unitario ? art.precio_unitario.toFixed(2) + '€' : '-'}</td>
                <td><strong>${art.total.toFixed(2)}€</strong></td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
    `;
}
```

### 2. **Editar Artículos al Procesar Factura**

```javascript
// Después de mostrar los datos extraídos, agregar tabla editable
if (datos.articulos && datos.articulos.length > 0) {
    html += `
        <div style="margin-top: 20px;">
            <h4>📦 Artículos Detectados</h4>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Descripción</th>
                        <th>Cant.</th>
                        <th>Unidad</th>
                        <th>Precio Unit.</th>
                        <th>Total</th>
                    </tr>
                </thead>
                <tbody id="articulosTableBody">
    `;
    
    datos.articulos.forEach((art, index) => {
        html += `
            <tr>
                <td><input type="text" value="${art.descripcion}" id="art_desc_${index}"></td>
                <td><input type="number" value="${art.cantidad}" id="art_cant_${index}" step="0.01"></td>
                <td><input type="text" value="${art.unidad}" id="art_unidad_${index}"></td>
                <td><input type="number" value="${art.precio_unitario || ''}" id="art_precio_${index}" step="0.01"></td>
                <td><input type="number" value="${art.total}" id="art_total_${index}" step="0.01"></td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
    `;
}
```

### 3. **Estadísticas de Artículos**

Crear un nuevo módulo "📊 Análisis de Gastos" que muestre:
- Gráfico de gasto por categoría
- Top 10 productos más comprados
- Evolución de precios
- Comparativa entre proveedores

---

## ⚠️ Notas Importantes

### 🎯 Precisión de la Extracción

La extracción automática de artículos depende de:
- **Calidad del PDF**: PDFs de buena calidad = mejor OCR
- **Formato de la factura**: Facturas estructuradas = mejor detección
- **Idioma**: Optimizado para español

**No todas las facturas tendrán artículos detectables**:
- ✅ Facturas con tabla detallada de productos
- ❌ Facturas con solo un concepto global
- ❌ Facturas manuscritas o de baja calidad

### 🔄 Validación

El sistema valida:
```python
# Coherencia: cantidad × precio ≈ total
calculado = cantidad * precio_unitario
if abs(calculado - total) < 1.0:  # Tolerancia 1€
    ✅ Artículo válido
else:
    ❌ Descartado
```

### 📝 Edición Manual

Si la IA no detecta artículos correctamente:
1. El frontend puede permitir agregar/editar artículos manualmente
2. Se envían en el campo `articulos` al crear el pago
3. Se guardan normalmente en la BD

---

## 🔍 Debugging

### Ver artículos extraídos en logs:

```python
# En app.py - función procesar_factura
app.logger.info(f"✅ ARTÍCULO encontrado: {descripcion} | {cantidad} {unidad} × {precio}€ = {total}€")
app.logger.info(f"✅ Total de {len(articulos_extraidos)} artículos extraídos")
```

### Ver artículos guardados:

```sql
SELECT 
    p.proveedor,
    p.fecha_pago,
    a.*
FROM articulo_factura a
INNER JOIN pago_proveedor p ON a.pago_proveedor_id = p.id_pago
ORDER BY a.fecha_creacion DESC
LIMIT 50;
```

---

## 📈 Beneficios a Largo Plazo

1. **Transparencia Total**: Saber exactamente en qué se gasta cada euro
2. **Optimización**: Identificar oportunidades de ahorro
3. **Auditoría**: Histórico completo de todas las compras
4. **Presupuesto**: Control detallado por categorías
5. **Negociación**: Datos para negociar mejores precios con proveedores
6. **Predicción**: Anticipar necesidades basándose en patrones

---

**✨ Sistema completo de gestión de artículos implementado y listo para usar.**
