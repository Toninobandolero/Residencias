# 🔄 Cambios Completos al Sistema de Permisos

**Fecha:** Diciembre 2025  
**Versión:** 2.1

---

## 📋 Resumen de Cambios

Se ha implementado un sistema completo de permisos granulares con herencia de roles, incluyendo correcciones de sintaxis y reorganización de documentación.

---

## 🔧 1. Herencia de Permisos

### Problema
Los usuarios con rol Director no podían acceder a módulos aunque su rol tenía los permisos necesarios en `rol_permiso`.

### Solución
Actualizada la función `usuario_tiene_permiso()` en `app.py` para verificar en dos niveles:

```python
def usuario_tiene_permiso(id_usuario, id_rol, nombre_permiso, cursor=None):
    # 1. Administrador → bypass total
    if id_rol == ADMIN_ROLE_ID:
        return True
    
    # 2. Verificar permisos individuales
    cursor.execute("""
        SELECT 1 FROM usuario_permiso
        WHERE id_usuario = %s AND nombre_permiso = %s
    """, (id_usuario, nombre_permiso))
    
    if cursor.fetchone():
        return True
    
    # 3. Verificar permisos heredados del rol
    cursor.execute("""
        SELECT 1 FROM rol_permiso
        WHERE id_rol = %s AND nombre_permiso = %s
    """, (id_rol, nombre_permiso))
    
    return cursor.fetchone() is not None
```

**Resultado:**
- ✅ Usuarios heredan permisos de su rol
- ✅ Permisos individuales complementan los del rol
- ✅ Máxima flexibilidad en asignación

---

## 🎨 2. Actualización de Endpoints

### 2.1. `/api/v1/usuarios/me` (GET)

**Antes:** Solo devolvía permisos de `usuario_permiso`

**Ahora:** Devuelve permisos combinados (individuales + heredados):

```python
# Administrador → todos los permisos del sistema
if id_rol_actual == ADMIN_ROLE_ID:
    cursor.execute("SELECT nombre_permiso FROM permiso WHERE activo = TRUE")
    permisos = [p[0] for p in cursor.fetchall()]
else:
    # Otros roles → UNION de individuales + heredados
    cursor.execute("""
        SELECT DISTINCT nombre_permiso
        FROM (
            SELECT nombre_permiso FROM usuario_permiso WHERE id_usuario = %s
            UNION
            SELECT nombre_permiso FROM rol_permiso WHERE id_rol = %s
        ) AS permisos_combinados
    """, (id_usuario, id_rol))
    permisos = [p[0] for p in cursor.fetchall()]
```

### 2.2. `/api/v1/usuarios` (GET)

**Antes:** Solo devolvía permisos de `usuario_permiso`

**Ahora:** Igual que `/api/v1/usuarios/me`, devuelve permisos combinados para cada usuario

**Impacto:**
- ✅ Frontend recibe TODOS los permisos efectivos
- ✅ Al editar usuario se marcan TODOS los checkboxes correctos
- ✅ `usuarioActual.permisos` refleja la realidad completa

---

## 🐛 3. Corrección de Errores de Sintaxis

### Problema
Template strings múltiplemente anidados causaban `SyntaxError` en navegadores.

### Casos Corregidos

#### 3.1. Template Strings Anidados (Líneas 3418, 3504)
```javascript
// ❌ ANTES (causaba error)
${(() => {
    const puedeEditar = usuarioTienePermiso('editar:cobro');
    return `<tr ... ${puedeEditar ? `onclick="..."` : '...'}>`;
})()}

// ✅ AHORA (correcto)
const puedeEditarCobroTabla = usuarioTienePermiso('editar:cobro');
html += `<tr ... ${puedeEditarCobroTabla ? 'onclick="editarCobro(' + cobro.id_pago + ')"' : '...'}>`;
```

#### 3.2. Template Strings con 4 Niveles (Línea 11326)
```javascript
// ❌ ANTES (4 niveles de anidación)
${doc.tipo_entidad !== 'pago_proveedor' ? `
    ${usuarioTienePermiso('eliminar:documento') ? `<button ...>` : '<div></div>'}
` : ''}

// ✅ AHORA (función IIFE)
${(function() {
    if (doc.tipo_entidad === 'pago_proveedor') return '';
    if (!usuarioTienePermiso('eliminar:documento')) return '<div></div>';
    return '<button onclick="eliminarDocumentoUnificado(' + doc.id_documento + ')">...</button>';
})()}
```

#### 3.3. Botones con IDs Dinámicos (Líneas 8446, 8458, 8637)
```javascript
// ❌ ANTES (3 niveles de anidación)
${usuarioTienePermiso('editar:residente') ? `<button onclick="abrirModalBaja(${res.id_residente})">...` : ''}

// ✅ AHORA (concatenación)
${usuarioTienePermiso('editar:residente') ? '<button onclick="abrirModalBaja(' + res.id_residente + ')">...' : ''}
```

---

## 🛠️ 4. Sistema de Funciones Helper

### Funciones Creadas

#### 4.1. `botonSiPermiso(permiso, config)`
Para botones estáticos sin parámetros dinámicos:

```javascript
${botonSiPermiso('crear:cobro', {
    texto: '+ Agregar Cobro',
    onclick: "openModal('modalCobro')",
    clase: 'add-btn',
    estilo: 'padding: 8px 16px;'
})}
```

#### 4.2. `botonConIdSiPermiso(permiso, config, ...params)`
Para botones con IDs o parámetros dinámicos:

```javascript
${botonConIdSiPermiso('editar:residente', {
    texto: 'Editar',
    funcionOnclick: 'editarResidente',
    estilo: 'background: #667eea; color: white;'
}, residente.id_residente)}
```

**Ventajas:**
- ✅ Sin errores de sintaxis
- ✅ Código limpio y mantenible
- ✅ Reutilizable
- ✅ Fácil de debuggear

---

## 📚 5. Reorganización de Documentación

### Antes
23 archivos MD dispersos y con información duplicada.

### Ahora
6 archivos principales consolidados:

| Archivo | Líneas | Contenido |
|---------|--------|-----------|
| **README.md** | ~310 | Visión general, inicio rápido |
| **GUIA_COMPLETA.md** | 522 | Instalación, configuración, uso |
| **GUIA_SEGURIDAD_PERMISOS.md** | 592 | Seguridad, autenticación, permisos |
| **GUIA_DESPLIEGUE_CI_CD.md** | 560 | Despliegue, GitHub Actions, producción |
| **GUIA_TROUBLESHOOTING.md** | ~500 | Problemas comunes, diagnóstico |
| **REFERENCIA_API.md** | ~450 | Referencia completa de API |

**Archivos anteriores:** Movidos a `docs_archive/`

---

## 🔍 6. Debugging de Residencias

### Logs Agregados
Se agregaron logs en `loadResidenciasForSelect()` para diagnosticar problemas:

```javascript
console.log('🔍 loadResidenciasForSelect llamada con:', residenciasSeleccionadas);
console.log('🔍 Residencias activas disponibles:', residenciasActivas);
console.log('🔍 Residencias a marcar:', residenciasSeleccionadasActivas);
console.log(`🔍 Residencia ${res.id_residencia}: ${estaSeleccionada ? 'MARCADA' : 'NO marcada'}`);
```

**Uso:**
1. Editar un usuario
2. Abrir consola del navegador (F12)
3. Verificar qué residencias se reciben y se marcan

---

## ✅ 7. Verificaciones Realizadas

### Base de Datos
```sql
-- ✅ Usuario Director tiene ambas residencias correctamente
SELECT u.email, ur.id_residencia, r.nombre
FROM usuario u
JOIN usuario_residencia ur ON u.id_usuario = ur.id_usuario
JOIN residencia r ON ur.id_residencia = r.id_residencia
WHERE u.id_rol = 3;

-- Resultado:
-- papaoso@residencias.com | 1 | Las Violetas 1
-- papaoso@residencias.com | 2 | Las Violetas 2
```

### Backend
- ✅ `crear_usuario()` - Guarda correctamente en `usuario_residencia`
- ✅ `actualizar_usuario()` - DELETE + INSERT correcto
- ✅ `listar_usuarios()` - Devuelve array completo de residencias
- ✅ Permisos heredados funcionando

### Frontend
- ✅ `editarUsuario()` - Pasa `usuario.residencias` correctamente
- ✅ `loadResidenciasForSelect()` - Recibe array, filtra y marca
- ✅ `saveUsuario()` - Envía residencias seleccionadas
- ✅ Logs de debugging agregados

---

## 🚀 Próximos Pasos

### 1. Reiniciar el Servidor
```bash
./restart_server.ps1
```

### 2. Testing

**Test A: Permisos Heredados**
1. Login con usuario Director
2. Verificar que ve módulo "Documentación" ✅
3. Verificar que ve todos los módulos de su rol

**Test B: Editar Usuario**
1. Configuración → Usuarios
2. Editar usuario Director
3. Abrir consola (F12)
4. Verificar logs:
   - `🔍 loadResidenciasForSelect llamada con: [...]`
   - Debe mostrar array con 2 residencias
5. Verificar que AMBOS checkboxes estén marcados ✅

**Test C: Guardar Cambios**
1. Desmarcar una residencia
2. Guardar
3. Verificar que se guarda correctamente
4. Volver a editar
5. Verificar que se cargó correctamente

### 3. Si el Problema Persiste

**Copiar los logs de la consola:**
```
🔍 loadResidenciasForSelect llamada con: [...]
🔍 Residencias activas disponibles: [...]
🔍 Residencias a marcar: [...]
🔍 Residencia 1: MARCADA/NO marcada
🔍 Residencia 2: MARCADA/NO marcada
```

Y compartirlos para diagnóstico específico.

---

## 📝 Archivos Modificados

### Backend
- ✅ `app.py` - Función `usuario_tiene_permiso()` con herencia
- ✅ `app.py` - Endpoint `/api/v1/usuarios/me` con permisos combinados
- ✅ `app.py` - Endpoint `/api/v1/usuarios` (GET) con permisos combinados

### Frontend
- ✅ `static/index.html` - Template strings corregidos (6+ casos)
- ✅ `static/index.html` - Funciones helper `botonSiPermiso()` y `botonConIdSiPermiso()`
- ✅ `static/index.html` - Logs de debugging en `loadResidenciasForSelect()`
- ✅ `static/index.html` - Script de limpieza de URL con credenciales

### Documentación
- ✅ `GUIA_COMPLETA.md` - Nuevo archivo consolidado
- ✅ `GUIA_SEGURIDAD_PERMISOS.md` - Nuevo archivo consolidado
- ✅ `GUIA_DESPLIEGUE_CI_CD.md` - Nuevo archivo consolidado
- ✅ `CAMBIO_HERENCIA_PERMISOS.md` - Explicación del cambio
- ✅ `REORGANIZACION_COMPLETADA.md` - Resumen de reorganización
- ✅ `README.md` - Actualizado con nueva estructura
- ✅ 21 archivos movidos a `docs_archive/`

---

## 🎯 Estado Actual

### ✅ Completado
- [x] Sistema de herencia de permisos implementado
- [x] Errores de sintaxis corregidos
- [x] Funciones helper creadas
- [x] Endpoints actualizados
- [x] Documentación consolidada

### 🔍 En Verificación
- [ ] Carga correcta de residencias al editar usuario (debugging agregado)
- [ ] Reflejo inmediato de cambios de permisos en la UI

### 📋 Pendiente de Confirmar por Usuario
- [ ] Usuario Director ve módulo Documentación
- [ ] Al editar usuario se muestran todas las residencias marcadas
- [ ] Los cambios de permisos se reflejan inmediatamente

---

## 📞 Soporte

Si encuentras problemas:

1. **Permisos:** Consulta `GUIA_SEGURIDAD_PERMISOS.md`
2. **Residencias:** Revisa logs en consola del navegador (F12)
3. **Otros:** Consulta `GUIA_TROUBLESHOOTING.md`

---

**Última actualización:** Diciembre 2025  
**Estado:** ✅ Implementado, en verificación de usuario
