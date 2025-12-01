# Guía de Migración de Endpoints al Nuevo Sistema de Autorización

## Resumen
Este documento describe los patrones de actualización necesarios para migrar todos los endpoints del sistema antiguo (usuario con una sola residencia) al nuevo sistema (usuario con múltiples residencias + permisos granulares).

## Patrones de Actualización

### Patrón 1: Reemplazar `g.id_residencia = X` por `validate_residencia_access()`

**ANTES:**
```python
if g.id_rol != 1 and id_residencia != g.id_residencia:
    return jsonify({'error': 'Sin permisos'}), 403
```

**DESPUÉS:**
```python
is_valid, error_response = validate_residencia_access(id_residencia)
if not is_valid:
    return error_response
```

### Patrón 2: Reemplazar `WHERE id_residencia = g.id_residencia` por `WHERE id_residencia IN (g.residencias_acceso)`

**ANTES:**
```python
if g.id_rol == 1:
    cursor.execute("SELECT * FROM tabla")
else:
    cursor.execute("SELECT * FROM tabla WHERE id_residencia = %s", (g.id_residencia,))
```

**DESPUÉS:**
```python
if g.id_rol == SUPER_ADMIN_ROLE_ID:
    cursor.execute("SELECT * FROM tabla")
else:
    if not g.residencias_acceso:
        return jsonify({'data': [], 'total': 0}), 200
    
    placeholders = ','.join(['%s'] * len(g.residencias_acceso))
    cursor.execute(f"SELECT * FROM tabla WHERE id_residencia IN ({placeholders})", tuple(g.residencias_acceso))
```

### Patrón 3: Agregar Decorador `@permiso_requerido()`

**ANTES:**
```python
@app.route('/api/v1/endpoint', methods=['GET'])
def mi_endpoint():
    # código...
```

**DESPUÉS:**
```python
@app.route('/api/v1/endpoint', methods=['GET'])
@permiso_requerido('leer:recurso')  # o 'escribir:recurso', etc.
def mi_endpoint():
    # código...
```

**Nota:** Super_admin tiene bypass automático en el decorador.

## Endpoints Ya Actualizados ✅

1. ✅ `GET /api/v1/residentes` - Listar residentes
2. ✅ `GET /api/v1/facturacion/cobros` - Listar cobros
3. ✅ `GET /api/v1/facturacion/proveedores` - Listar pagos a proveedores
4. ✅ `GET /api/v1/proveedores` - Listar proveedores
5. ✅ `POST /api/v1/facturacion/cobros/generar-previstos` - Generar cobros previstos
6. ✅ `GET /api/v1/residentes/<id>` - Obtener residente (usa validate_residencia_access)
7. ✅ `PUT /api/v1/residentes/<id>` - Actualizar residente (usa validate_residencia_access)
8. ✅ `POST /api/v1/residentes/<id>/baja` - Dar baja (usa validate_residencia_access)
9. ✅ `POST /api/v1/residentes/<id>/alta` - Dar alta (usa validate_residencia_access)
10. ✅ `DELETE /api/v1/residentes/<id>` - Eliminar residente (usa validate_residencia_access)
11. ✅ `GET /api/v1/facturacion/cobros/<id>` - Obtener cobro (usa validate_residencia_access)
12. ✅ `PUT /api/v1/facturacion/cobros/<id>` - Actualizar cobro (usa validate_residencia_access)
13. ✅ `DELETE /api/v1/facturacion/cobros/<id>` - Eliminar cobro (usa validate_residencia_access)

## Endpoints Pendientes de Actualizar ⚠️

### Estadísticas de Cobros
**Archivo:** `app.py`, función `estadisticas_cobros()` (línea ~1533)

**Cambios necesarios:**
- Actualizar consultas que usan `g.id_residencia` por filtros IN
- Aplicar decorador `@permiso_requerido('leer:estadisticas')` si aplica

### Últimos Cobros Completados
**Archivo:** `app.py`, función `ultimos_cobros_completados()` (línea ~2136)

**Cambios necesarios:**
- Actualizar consultas que usan `g.id_residencia` por filtros IN

### Habitaciones Ocupadas
**Archivo:** `app.py`, función `obtener_habitaciones_ocupadas()` (línea ~691)

**Cambios necesarios:**
- Ya usa `validate_residencia_access` ✅
- Verificar que funcione correctamente con múltiples residencias

### Crear Residente
**Archivo:** `app.py`, función `crear_residente()` (línea ~1087)

**Cambios necesarios:**
- Validar que el `id_residencia` del residente esté en `g.residencias_acceso`
- Aplicar decorador `@permiso_requerido('escribir:residente')`

### Crear Cobro
**Archivo:** `app.py`, función `crear_cobro()` (línea ~1493)

**Cambios necesarios:**
- Ya usa `validate_residencia_access` ✅
- Verificar que funcione correctamente

### Endpoints de Proveedores
**Archivo:** `app.py`, funciones relacionadas con proveedores

**Cambios necesarios:**
- Verificar que todos los endpoints de proveedores usen filtros IN
- Agregar decoradores `@permiso_requerido` apropiados

### Endpoints de Personal
**Archivo:** `app.py`, funciones relacionadas con personal

**Cambios necesarios:**
- Actualizar consultas para usar filtros IN
- Agregar decoradores `@permiso_requerido` apropiados

### Endpoints de Turnos
**Archivo:** `app.py`, funciones de turnos_extra

**Cambios necesarios:**
- Verificar que los filtros por `id_residencia` usen IN
- Los endpoints de turnos_extra ya filtran correctamente, verificar que usen el nuevo sistema

## Checklist de Actualización

Para cada endpoint pendiente:

- [ ] Reemplazar `g.id_residencia` por `g.residencias_acceso` con filtro IN
- [ ] Reemplazar validaciones `if g.id_rol != 1 and X != g.id_residencia` por `validate_residencia_access()`
- [ ] Agregar decorador `@permiso_requerido()` si aplica
- [ ] Reemplazar `if g.id_rol == 1` por `if g.id_rol == SUPER_ADMIN_ROLE_ID`
- [ ] Verificar que super_admin tenga acceso sin filtros
- [ ] Verificar que usuarios normales solo vean sus residencias asignadas
- [ ] Probar con múltiples residencias asignadas

## Notas Importantes

1. **Super Admin:** Siempre usa `g.id_rol == SUPER_ADMIN_ROLE_ID` (constante = 1)
2. **Lista vacía:** Si `g.residencias_acceso` está vacía y NO es super_admin, retornar 403 o datos vacíos
3. **Validación:** Usar `validate_residencia_access()` después de obtener registros de BD
4. **Decoradores:** El decorador `@permiso_requerido()` verifica permisos pero NO filtra por residencia
5. **Filtros:** Los filtros por residencia deben aplicarse manualmente en las consultas SQL

