# 📋 Lógica de Cobros Previstos - Sistema Violetas

## 🔄 Flujo Completo

### 1. **Generación Automática** (Backend)

**Endpoint:** `POST /api/v1/facturacion/cobros/generar-previstos`

**Condiciones para generar un cobro previsto:**

```python
# Un residente debe cumplir TODAS estas condiciones:
- activo = TRUE
- costo_habitacion IS NOT NULL
- costo_habitacion > 0
- id_residencia = (la del usuario autenticado)
```

**Lógica de generación:**

1. **Selección de residentes:**
   ```sql
   SELECT id_residente, nombre, apellido, costo_habitacion, metodo_pago_preferido
   FROM residente
   WHERE id_residencia = %s 
     AND activo = TRUE 
     AND costo_habitacion IS NOT NULL 
     AND costo_habitacion > 0
   ```

2. **Cálculo de fecha prevista según método de pago:**
   - **Transferencia**: Día 3 del mes siguiente
   - **Remesa**: Día 30 del mes siguiente
   - **Otros** (metálico, bizum, etc.): Día 5 del mes siguiente

3. **Prevención de duplicados:**
   - Verifica si ya existe un cobro previsto para ese residente en ese mes
   - Si existe, NO crea otro (evita duplicados)

4. **Creación del cobro previsto:**
   ```python
   INSERT INTO pago_residente (
       id_residente, id_residencia, monto, 
       fecha_pago,           # NULL (no hay fecha de pago aún)
       fecha_prevista,        # Fecha calculada según método de pago
       mes_pagado,           # Formato: 'YYYY-MM'
       concepto,              # "Pago mensual habitación - Nombre Apellido"
       metodo_pago,           # Del residente
       estado,                # 'pendiente' (siempre)
       es_cobro_previsto      # TRUE (siempre)
   )
   ```

---

### 2. **Obtención de Cobros** (Backend)

**Endpoint:** `GET /api/v1/facturacion/cobros`

**Query SQL:**
```sql
SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
       p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
       p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion
FROM pago_residente p
JOIN residente r ON p.id_residente = r.id_residente
WHERE p.id_residencia = %s
ORDER BY COALESCE(p.fecha_prevista, p.fecha_pago) DESC, p.fecha_creacion DESC
```

**Retorna:**
- Todos los cobros (previstos y reales) de la residencia
- Incluye el campo `es_cobro_previsto` (boolean)

---

### 3. **Filtrado en el Frontend**

**Ubicación:** `static/index.html` - Función `loadFacturacion()`

#### Paso 1: Verificar si hay cobros previstos

```javascript
// Si no hay cobros previstos, intentar generarlos automáticamente
const tieneCobrosPrevistos = cobrosData.cobros && cobrosData.cobros.length > 0 && 
                            cobrosData.cobros.some(c => c.es_cobro_previsto === true);

if (!tieneCobrosPrevistos) {
    // Llamar a POST /api/v1/facturacion/cobros/generar-previstos
    // Recargar los cobros después de generarlos
}
```

#### Paso 2: Filtrar cobros previstos

```javascript
// Filtrar todos los cobros que son previstos
const todosCobrosPrevistos = cobrosData.cobros.filter(c => {
    const esPrevisto = c.es_cobro_previsto === true || 
                      c.es_cobro_previsto === 'true' || 
                      c.es_cobro_previsto === 'True' ||
                      c.es_cobro_previsto === 1;
    return esPrevisto;
});
```

**Condición:** `es_cobro_previsto` debe ser `true` (acepta diferentes formatos)

#### Paso 3: Separar por estado

```javascript
// Cobros PENDIENTES (se muestran en "Cobros Previstos")
const cobrosPrevistos = todosCobrosPrevistos.filter(c => {
    const estado = (c.estado || '').toLowerCase().trim();
    return estado === 'pendiente' || estado === '' || !c.estado;
});

// Cobros COMPLETADOS (se muestran en "Cobros Completados")
const cobrosCompletados = todosCobrosPrevistos.filter(c => {
    const estado = (c.estado || '').toLowerCase();
    return estado === 'cobrado' || estado === 'completado';
});
```

**Condiciones:**
- **Pendientes**: `estado === 'pendiente'` O `estado === ''` O `estado === null`
- **Completados**: `estado === 'cobrado'` O `estado === 'completado'`

---

## 📊 Resumen de Condiciones

### Para que un cobro previsto se MUESTRE como PENDIENTE:

✅ **Debe cumplir TODAS estas condiciones:**

1. `es_cobro_previsto === true` (o equivalente)
2. `estado === 'pendiente'` O `estado === ''` O `estado === null`
3. `id_residencia` coincide con la del usuario autenticado

### Para que un cobro previsto se MUESTRE como COMPLETADO:

✅ **Debe cumplir TODAS estas condiciones:**

1. `es_cobro_previsto === true` (o equivalente)
2. `estado === 'cobrado'` O `estado === 'completado'`
3. `id_residencia` coincide con la del usuario autenticado

---

## 🔍 Debug y Diagnóstico

El sistema incluye logs de depuración en la consola del navegador:

```javascript
console.log('🔍 Debug cobros:', {
    total: cobrosData.cobros?.length || 0,
    todosPrevistos: todosCobrosPrevistos.length,
    pendientes: cobrosPrevistos.length,
    completados: cobrosCompletados.length,
    muestra: todosCobrosPrevistos.slice(0, 3).map(c => ({
        id: c.id_pago,
        residente: c.residente,
        estado: c.estado,
        es_previsto: c.es_cobro_previsto
    }))
});
```

**Para ver estos logs:**
1. Abre la consola del navegador (F12 → Console)
2. Ve a la sección de Facturación
3. Revisa los logs que muestran el conteo y ejemplos

---

## ⚠️ Problemas Comunes

### No se muestran cobros previstos pendientes

**Posibles causas:**

1. **No hay residentes que cumplan las condiciones:**
   - Verificar que hay residentes activos
   - Verificar que tienen `costo_habitacion` definido y > 0

2. **Los cobros tienen estado diferente a 'pendiente':**
   - Verificar en la BD: `SELECT estado FROM pago_residente WHERE es_cobro_previsto = TRUE`
   - Si el estado es NULL o vacío, debería mostrarse (el filtro lo acepta)

3. **`es_cobro_previsto` no es `true`:**
   - Verificar en la BD: `SELECT es_cobro_previsto FROM pago_residente`
   - Debe ser `TRUE` (booleano) o `1` (entero)

4. **Los cobros fueron marcados como 'cobrado':**
   - Si el estado es 'cobrado', aparecerán en "Cobros Completados", no en "Cobros Previstos"

### Solución de diagnóstico:

```sql
-- Ver todos los cobros previstos y su estado
SELECT 
    id_pago,
    id_residente,
    estado,
    es_cobro_previsto,
    fecha_prevista,
    fecha_pago
FROM pago_residente
WHERE es_cobro_previsto = TRUE
ORDER BY fecha_prevista DESC;
```

---

## 🔄 Flujo Visual

```
1. Usuario abre Facturación
   ↓
2. Frontend llama GET /api/v1/facturacion/cobros
   ↓
3. Backend retorna TODOS los cobros (previstos + reales)
   ↓
4. Frontend verifica si hay cobros previstos
   ↓
5. Si NO hay → Llama POST /api/v1/facturacion/cobros/generar-previstos
   ↓
6. Backend genera cobros para residentes activos con costo_habitacion
   ↓
7. Frontend recarga los cobros
   ↓
8. Frontend filtra:
   - es_cobro_previsto === true
   - estado === 'pendiente' → "Cobros Previstos"
   - estado === 'cobrado' → "Cobros Completados"
   ↓
9. Muestra en la interfaz
```

---

## 📝 Notas Importantes

1. **Generación automática:** Solo se genera si NO hay cobros previstos existentes
2. **Prevención de duplicados:** No se crean dos cobros previstos para el mismo residente en el mismo mes
3. **Filtrado por residencia:** Todo se filtra automáticamente por `id_residencia` del token
4. **Estado por defecto:** Los cobros previstos se crean con `estado = 'pendiente'`
5. **Fecha de pago:** Los cobros previstos tienen `fecha_pago = NULL` hasta que se marcan como cobrados

