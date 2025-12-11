# 🔧 Solución: Problema al Editar Usuarios

**Fecha:** Diciembre 2025  
**Problema:** Al editar usuarios, el rol y las residencias no se guardaban/mostraban correctamente.

---

## 📋 Problema Reportado

### Síntomas
1. ❌ El rol no se mostraba correctamente al abrir el modal de edición
2. ❌ Las residencias aparecían desmarcadas aunque estaban guardadas en BD
3. ❌ Los cambios no se persistían después de guardar

### Diagnóstico con Logs

Los logs revelaron que `loadResidenciasForSelect()` se llamaba **DOS VECES**:

```
Primera llamada (✅ correcta):
🔍 loadResidenciasForSelect llamada con: [{id_residencia: 1, ...}, {id_residencia: 2, ...}]
🔍 Residencia 1 (Las Violetas 1): MARCADA
🔍 Residencia 2 (Las Violetas 2): MARCADA

Segunda llamada (❌ incorrecta):
🔍 loadResidenciasForSelect llamada con: []
🔍 Residencia 1 (Las Violetas 1): NO marcada
🔍 Residencia 2 (Las Violetas 2): NO marcada
```

La segunda llamada **sobrescribía** los datos correctos con un array vacío.

---

## 🔍 Causa Raíz

### El Problema

En `loadRolesForSelect()` se configuraba un evento `onchange` en el select de rol:

```javascript
select.onchange = function() {
    // Cuando cambia el rol, automáticamente marca/desmarca permisos
    // según el rol seleccionado (Administrador, Director, Personal)
    // ...
};
```

### La Secuencia del Error

1. `editarUsuario()` llamaba a `loadRolesForSelect()`
2. `loadRolesForSelect()` configuraba el evento `onchange`
3. `editarUsuario()` establecía el valor: `selectRol.value = usuario.id_rol`
4. **Establecer el value DISPARABA el evento `onchange`**
5. El `onchange` llamaba internamente a funciones que sobrescribían los datos

### Por Qué Pasaba

JavaScript dispara eventos `onchange` incluso cuando el valor se establece programáticamente, no solo cuando el usuario cambia manualmente el select.

---

## ✅ Solución Implementada

### Código Corregido

```javascript
async function editarUsuario(idUsuario) {
    // ... obtener datos del usuario ...
    
    // Cargar roles PRIMERO
    await loadRolesForSelect();
    
    // 🔑 CLAVE: Deshabilitar onchange temporalmente
    const selectRol = document.getElementById('usuario_id_rol');
    const originalOnchange = selectRol.onchange;
    selectRol.onchange = null;  // ← Deshabilitar
    
    // Ahora SÍ podemos establecer el valor sin disparar eventos
    selectRol.value = usuario.id_rol;
    
    // Cargar residencias (ahora no se sobrescribirán)
    await loadResidenciasForSelect(usuario.residencias || []);
    
    // Cargar permisos
    await loadModulosForSelect(usuario.permisos || []);
    
    // 🔑 CLAVE: Restaurar onchange DESPUÉS de cargar todo
    selectRol.onchange = originalOnchange;  // ← Restaurar
    
    // Abrir modal
    openModal('modalUsuario');
}
```

### Pasos de la Solución

1. **Guardar referencia** al `onchange` original
2. **Deshabilitar** temporalmente: `selectRol.onchange = null`
3. **Establecer valor** del rol sin disparar eventos
4. **Cargar residencias y permisos** sin interferencias
5. **Restaurar** el evento `onchange` para que funcione normalmente después

---

## 🎯 Resultado

### Antes ❌
```
Editar usuario:
  → Se dispara onchange al establecer rol
  → onchange sobrescribe residencias con []
  → Usuario ve checkboxes vacíos
  → Guardar elimina residencias
```

### Después ✅
```
Editar usuario:
  → onchange deshabilitado durante carga
  → Se establece rol correctamente
  → Se cargan residencias correctamente
  → Se cargan permisos correctamente
  → onchange restaurado para uso normal
  → Usuario ve todos los datos correctos
  → Guardar mantiene todos los datos
```

---

## 📊 Verificación

### Base de Datos
```sql
-- Verificar que datos están guardados correctamente
SELECT u.email, u.id_rol, r.nombre as rol,
       ARRAY_AGG(ur.id_residencia) as residencias
FROM usuario u
JOIN rol r ON u.id_rol = r.id_rol
LEFT JOIN usuario_residencia ur ON u.id_usuario = ur.id_usuario
WHERE u.email = 'papaoso@residencias.com'
GROUP BY u.id_usuario, u.email, u.id_rol, r.nombre;

-- Resultado esperado:
-- email: papaoso@residencias.com
-- id_rol: 3 (Director)
-- residencias: [1, 2]
```

### Frontend
1. Editar usuario papaoso@residencias.com
2. Verificar que aparece:
   - ✅ Rol: Director (seleccionado)
   - ✅ Residencia "Las Violetas 1" (marcada)
   - ✅ Residencia "Las Violetas 2" (marcada)
   - ✅ 42 permisos marcados (heredados del rol)

### Guardar Cambios
1. Cambiar rol de Director a Personal
2. Guardar
3. Cerrar y reabrir modal
4. Verificar que aparece "Personal" seleccionado ✅

---

## 🛠️ Archivos Modificados

### `static/index.html`

**Función `editarUsuario()`:**
- ✅ Agregada lógica para deshabilitar/restaurar `onchange`
- ✅ Removidos logs de debugging
- ✅ Comentarios explicativos añadidos

**Función `loadResidenciasForSelect()`:**
- ✅ Removidos logs de debugging
- ✅ Lógica de carga intacta

**Función `saveUsuario()`:**
- ✅ Removidos logs de debugging
- ✅ Lógica de guardado intacta

### `app.py`

**Función `actualizar_usuario()`:**
- ✅ Removidos logs de debugging
- ✅ Lógica de actualización intacta (ya funcionaba correctamente)

---

## 📚 Lecciones Aprendidas

### 1. Eventos en JavaScript
Los eventos `onchange`, `onclick`, etc. se disparan tanto por:
- ✅ Acciones del usuario (click, cambio manual)
- ✅ Cambios programáticos (`element.value = newValue`)

**Solución:** Deshabilitar temporalmente si no quieres que se disparen.

### 2. Debugging con Logs
Los logs fueron cruciales para identificar:
- Cuántas veces se llamaba una función
- Qué parámetros recibía cada vez
- En qué orden ocurrían las llamadas

**Recomendación:** Agregar logs temporales cuando algo falla de forma intermitente.

### 3. Estado vs Eventos
Cuando cargas datos programáticamente:
- **Estado:** Los datos en memoria
- **Eventos:** Reacciones automáticas a cambios

Hay que controlar cuándo quieres que los eventos se disparen y cuándo no.

---

## 🚀 Testing Post-Solución

### Test 1: Editar Usuario Existente ✅
```
1. Login como Administrador
2. Configuración → Usuarios
3. Click "Editar" en usuario Director
4. Verificar:
   ✓ Rol correcto seleccionado
   ✓ Residencias correctas marcadas
   ✓ Permisos correctos marcados
```

### Test 2: Cambiar Rol ✅
```
1. Editar usuario
2. Cambiar rol de Director a Personal
3. Guardar
4. Recargar página
5. Editar mismo usuario
6. Verificar:
   ✓ Ahora aparece como "Personal"
   ✓ Residencias se mantienen
```

### Test 3: Cambiar Residencias ✅
```
1. Editar usuario con 2 residencias
2. Desmarcar una residencia
3. Guardar
4. Recargar página
5. Editar mismo usuario
6. Verificar:
   ✓ Solo aparece 1 residencia marcada
```

### Test 4: Evento onchange Funciona ✅
```
1. Crear nuevo usuario (modal vacío)
2. Seleccionar rol "Director" manualmente
3. Verificar:
   ✓ Los permisos se marcan automáticamente
   ✓ El evento onchange SÍ funciona
```

---

## 🎯 Estado Final

✅ **Problema Resuelto Completamente**

- ✅ Rol se carga y guarda correctamente
- ✅ Residencias se cargan y guardan correctamente
- ✅ Permisos se cargan y guardan correctamente
- ✅ Evento `onchange` funciona correctamente al crear usuarios nuevos
- ✅ Sin efectos secundarios ni regresiones

---

## 📞 Soporte

Si el problema persiste:

1. **Verificar en BD:**
   ```sql
   SELECT * FROM usuario WHERE id_usuario = X;
   SELECT * FROM usuario_residencia WHERE id_usuario = X;
   ```

2. **Limpiar caché:**
   ```
   Cmd+Shift+R (Mac) o Ctrl+Shift+R (Windows)
   ```

3. **Consultar:**
   - `GUIA_TROUBLESHOOTING.md` - Problemas comunes
   - `CAMBIOS_SISTEMA_PERMISOS_COMPLETO.md` - Cambios recientes

---

**Última actualización:** Diciembre 2025  
**Estado:** ✅ Resuelto y probado
