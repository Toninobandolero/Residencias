# Revisión de Permisos en Endpoints

## 📋 Resumen de Incongruencias Encontradas

### ❌ ENDPOINTS SIN PERMISOS (deberían tenerlos)

#### COBROS (Facturación)

1. **GET /api/v1/facturacion/cobros** - `listar_cobros()`
   - ❌ Sin `@permiso_requerido`
   - ✅ Debería tener: `@permiso_requerido('leer:cobro')`

2. **POST /api/v1/facturacion/cobros** - `crear_cobro()`
   - ❌ Sin `@permiso_requerido`
   - ✅ Debería tener: `@permiso_requerido('crear:cobro')`

3. **POST /api/v1/facturacion/cobros/generar-previstos** - `generar_cobros_previstos()`
   - ❌ Sin `@permiso_requerido`
   - ✅ Debería tener: `@permiso_requerido('crear:cobro')`

4. **GET /api/v1/facturacion/cobros/estadisticas** - `estadisticas_cobros()`
   - ❌ Sin `@permiso_requerido`
   - ✅ Debería tener: `@permiso_requerido('leer:cobro')`

5. **GET /api/v1/facturacion/cobros/ultimos-completados** - `ultimos_cobros_completados()`
   - ❌ Sin `@permiso_requerido`
   - ✅ Debería tener: `@permiso_requerido('leer:cobro')`

6. **GET /api/v1/facturacion/cobros/<id>** - `obtener_cobro()`
   - ❌ Sin `@permiso_requerido`
   - ✅ Debería tener: `@permiso_requerido('leer:cobro')`

7. **POST /api/v1/facturacion/cobros/normalizar-conceptos** - `normalizar_conceptos_cobros()`
   - ❌ Sin `@permiso_requerido`
   - ✅ Debería tener: `@permiso_requerido('editar:cobro')`

8. **PUT /api/v1/facturacion/cobros/<id>** - `actualizar_cobro()`
   - ❌ Sin `@permiso_requerido`
   - ✅ Debería tener: `@permiso_requerido('editar:cobro')`

9. **DELETE /api/v1/facturacion/cobros/<id>** - `eliminar_cobro()`
   - ❌ Sin `@permiso_requerido`
   - ⚠️ No existe `eliminar:cobro` en módulos, pero debería tenerlo

#### PAGOS A PROVEEDORES

10. **GET /api/v1/facturacion/proveedores** - `listar_pagos_proveedores()`
    - ❌ Sin `@permiso_requerido`
    - ✅ Debería tener: `@permiso_requerido('leer:pago_proveedor')`

11. **GET /api/v1/facturacion/proveedores/<id>** - `obtener_pago_proveedor()`
    - ❌ Sin `@permiso_requerido`
    - ✅ Debería tener: `@permiso_requerido('leer:pago_proveedor')`

12. **PUT /api/v1/facturacion/proveedores/<id>** - `actualizar_pago_proveedor()`
    - ❌ Sin `@permiso_requerido`
    - ✅ Debería tener: `@permiso_requerido('editar:pago_proveedor')`

13. **DELETE /api/v1/facturacion/proveedores/<id>** - `eliminar_pago_proveedor()`
    - ❌ Sin `@permiso_requerido`
    - ⚠️ No existe `eliminar:pago_proveedor` en módulos, pero debería tenerlo

#### PROVEEDORES

14. **GET /api/v1/proveedores/<id>** - `obtener_proveedor()`
    - ❌ Sin `@permiso_requerido`
    - ✅ Debería tener: `@permiso_requerido('leer:proveedor')`

15. **PUT /api/v1/proveedores/<id>** - `actualizar_proveedor()`
    - ❌ Sin `@permiso_requerido`
    - ⚠️ Usa `escribir:proveedor` (que existe), pero debería usar `editar:proveedor` o agregar validación

16. **POST /api/v1/proveedores/<id>/baja** - `dar_baja_proveedor()`
    - ❌ Sin `@permiso_requerido`
    - ✅ Debería tener: `@permiso_requerido('editar:proveedor')` o `eliminar:proveedor`

---

### ✅ ENDPOINTS CON PERMISOS CORRECTOS

1. ✅ **POST /api/v1/facturacion/cobros/regenerar-historicos** - `@permiso_requerido('crear:cobro')`
2. ✅ **POST /api/v1/facturacion/proveedores** - `@permiso_requerido('crear:pago_proveedor')`
3. ✅ **POST /api/v1/facturacion/procesar-factura** - `@permiso_requerido('crear:pago_proveedor')`
4. ✅ **GET /api/v1/proveedores** - `@permiso_requerido('leer:proveedor')`
5. ✅ **POST /api/v1/proveedores** - `@permiso_requerido('escribir:proveedor')`

---

## 🔍 PROBLEMAS ADICIONALES ENCONTRADOS

### 1. Permisos Faltantes en Módulos

- ❌ `eliminar:cobro` - Existe en `inicializar_permisos.py` pero NO en `listar_modulos()` (línea 7294-7305)
- ❌ `eliminar:pago_proveedor` - Existe en `inicializar_permisos.py` pero NO en `listar_modulos()`

### 2. Inconsistencia en Nombres de Permisos

- `escribir:proveedor` vs `editar:proveedor` - Se usa `escribir:proveedor` para crear, pero debería ser consistente
- `escribir:pago_proveedor` existe pero se cambió a usar `crear:pago_proveedor` (correcto)

### 3. Permisos Redundantes

- `escribir:proveedor` y `escribir:pago_proveedor` son redundantes con `crear`/`editar`
- Podrían eliminarse o usarse como "permisos combo" que cubren ambos

---

## 📝 RECOMENDACIONES

1. **Agregar `@permiso_requerido` a todos los endpoints listados arriba**
2. **Agregar `eliminar:cobro` y `eliminar:pago_proveedor` al módulo de Facturación en `listar_modulos()`**
3. **Unificar el uso de permisos: usar `crear`/`editar`/`eliminar` de forma consistente**
4. **Considerar mantener `escribir` solo como alias o eliminarlo completamente**
