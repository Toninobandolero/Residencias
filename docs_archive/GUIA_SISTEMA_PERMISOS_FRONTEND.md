# Guía del Sistema de Permisos en Frontend

## Problema Original

Cuando implementamos el sistema de permisos, usábamos template strings anidados que causaban errores de sintaxis:

```javascript
// ❌ INCORRECTO - Causa SyntaxError
${usuarioTienePermiso('crear:documento') ? `<button onclick="agregarDocumento(${idResidente})">Botón</button>` : ''}
```

**Problema:** JavaScript no puede parsear correctamente template strings con más de 2 niveles de anidación, especialmente cuando hay variables dinámicas (`${idResidente}`) dentro.

## Solución Elegante: Funciones Helper

Hemos creado dos funciones helper que generan botones de forma limpia y segura:

### 1. `botonSiPermiso()` - Para botones estáticos

**Uso:** Botones simples sin parámetros dinámicos en el onclick.

```javascript
// ✅ CORRECTO
${botonSiPermiso('crear:cobro', {
    texto: '+ Agregar Cobro',
    onclick: "openModal('modalCobro')",
    clase: 'add-btn',
    estilo: 'padding: 8px 16px; font-size: 14px;'
})}
```

**Parámetros:**
- `permiso` (string): Nombre del permiso requerido
- `config` (object):
  - `texto`: Texto del botón
  - `onclick`: Código JavaScript a ejecutar (string literal)
  - `id`: ID del botón (opcional)
  - `clase`: Clases CSS (default: 'add-btn')
  - `estilo`: Estilos inline
  - `icono`: HTML del icono (opcional)

### 2. `botonConIdSiPermiso()` - Para botones dinámicos

**Uso:** Botones con parámetros dinámicos (IDs, etc.) en el onclick.

```javascript
// ✅ CORRECTO
${botonConIdSiPermiso('crear:documento', {
    texto: '+ Subir Documento',
    funcionOnclick: 'agregarDocumento',
    estilo: 'padding: 8px 20px; background: #28a745; color: white;'
}, idResidente)}

// Para múltiples parámetros:
${botonConIdSiPermiso('eliminar:documento', {
    texto: 'Eliminar',
    funcionOnclick: 'eliminarDocumento',
    estilo: '...'
}, doc.id_documento, idResidente)}
```

**Parámetros:**
- `permiso` (string): Nombre del permiso requerido
- `config` (object):
  - `texto`: Texto del botón
  - `funcionOnclick`: Nombre de la función (sin paréntesis ni parámetros)
  - `idBtn`: ID del botón (opcional)
  - `clase`: Clases CSS (opcional)
  - `estilo`: Estilos inline
  - `icono`: HTML del icono (opcional)
- `...params`: Lista de parámetros que se pasarán a la función onclick

**Resultado:** Genera `onclick="nombreFuncion(param1, param2, ...)"`

## Ejemplos de Uso

### Ejemplo 1: Botón simple

```javascript
// Botón para abrir modal
${botonSiPermiso('crear:residente', {
    texto: '+ Agregar Residente',
    onclick: "openModal('modalResidente')",
    clase: 'add-btn',
    estilo: 'padding: 8px 16px;'
})}
```

### Ejemplo 2: Botón con ID dinámico

```javascript
// Botón para editar residente específico
${botonConIdSiPermiso('editar:residente', {
    texto: 'Editar',
    funcionOnclick: 'editarResidente',
    clase: 'btn-editar',
    estilo: 'background: #667eea; color: white;'
}, residente.id_residente)}
```

### Ejemplo 3: Múltiples botones

```javascript
<div style="display: flex; gap: 10px;">
    ${botonConIdSiPermiso('editar:residente', {
        texto: 'Dar de Alta',
        funcionOnclick: 'reactivarResidente',
        estilo: 'background: #28a745; color: white;'
    }, res.id_residente)}
    
    ${botonConIdSiPermiso('eliminar:residente', {
        texto: 'Eliminar',
        funcionOnclick: 'confirmarEliminarResidente',
        estilo: 'background: #dc3545; color: white;'
    }, res.id_residente)}
</div>
```

## Ventajas de Este Sistema

✅ **Sin errores de sintaxis**: No más template strings anidados
✅ **Código limpio**: Más legible y mantenible
✅ **Reutilizable**: Usar en cualquier parte del código
✅ **Seguro**: Maneja automáticamente la verificación de permisos
✅ **Flexible**: Soporta cualquier número de parámetros
✅ **Escalable**: Fácil agregar más funcionalidades

## Reglas de Uso

### ✅ HACER

1. Usar `botonSiPermiso()` para botones simples sin IDs dinámicos
2. Usar `botonConIdSiPermiso()` para botones con IDs o parámetros dinámicos
3. Separar la generación de HTML de la lógica de permisos
4. Usar concatenación (`+`) en lugar de template strings anidados cuando sea necesario

### ❌ NO HACER

1. **NUNCA** usar template strings anidados con más de 2 niveles:
   ```javascript
   // ❌ MAL
   ${permiso ? `<button onclick="func(${id})">...</button>` : ''}
   ```

2. **NUNCA** poner variables dinámicas dentro de template strings anidados:
   ```javascript
   // ❌ MAL
   ${usuarioTienePermiso('x') ? `${variable}` : ''}
   ```

3. **NUNCA** anidar operadores ternarios dentro de template strings dentro de template strings

## Migrando Código Antiguo

### Antes (problemático):
```javascript
${usuarioTienePermiso('editar:residente') ? `<button type="button" onclick="abrirModalBaja(${res.id_residente})" style="padding: 10px 20px; background: #dc3545; color: white;">
    <img src="/static/icons/medical/user-x.svg" alt="Dar de baja"> Dar de Baja
</button>` : ''}
```

### Después (correcto):
```javascript
${botonConIdSiPermiso('editar:residente', {
    texto: '<img src="/static/icons/medical/user-x.svg" alt="Dar de baja" style="width: 16px; height: 16px;"> Dar de Baja',
    funcionOnclick: 'abrirModalBaja',
    estilo: 'padding: 10px 20px; background: #dc3545; color: white;'
}, res.id_residente)}
```

## Verificación de Permisos

El sistema usa la función `usuarioTienePermiso(nombrePermiso)` que:

1. Verifica si el usuario es Administrador (id_rol = 2) → permite TODO
2. Si no, verifica en `usuarioActual.permisos` si tiene el permiso específico
3. Retorna `true` si tiene permiso, `false` si no

## Testing

Para verificar que el sistema funciona:

1. Crear usuario con permisos limitados
2. Iniciar sesión con ese usuario
3. Verificar que solo aparecen los botones correspondientes a sus permisos
4. Verificar que NO hay errores de sintaxis en la consola del navegador

## Soporte

Si encuentras un error de sintaxis relacionado con permisos:

1. Identifica la línea exacta del error
2. Busca template strings anidados (`${...}` dentro de `` `...` ``)
3. Reemplaza con una de las funciones helper
4. Si el botón tiene parámetros dinámicos, usa `botonConIdSiPermiso()`
5. Si es estático, usa `botonSiPermiso()`
