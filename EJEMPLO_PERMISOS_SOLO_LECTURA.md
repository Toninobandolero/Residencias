# Ejemplo: Usuario con Solo Permisos de Lectura

## Escenario

Un usuario tiene permiso de **solo lectura** para Documentación:
- ✅ Tiene: `leer:documento`
- ❌ NO tiene: `crear:documento`
- ❌ NO tiene: `editar:documento`
- ❌ NO tiene: `eliminar:documento`

## ¿Qué Puede Hacer Este Usuario?

### ✅ PUEDE (Con `leer:documento`)

1. **Ver el módulo de Documentación**
   - El botón "Documentación" aparece en el dashboard
   - Puede hacer clic y acceder al módulo

2. **Ver la lista de documentos**
   - Ve todos los documentos de las residencias a las que tiene acceso
   - Ve información: nombre archivo, tipo, categoría, fecha, etc.

3. **Usar filtros**
   - Puede filtrar por residencia, tipo de entidad, categoría
   - Puede buscar documentos por texto
   - Puede limpiar filtros

4. **Ver documentos**
   - Puede hacer clic en el botón "Ver" (ojo)
   - Se abre el documento en una nueva pestaña

5. **Descargar documentos**
   - Puede hacer clic en el botón "Descargar" (flecha hacia abajo)
   - Descarga el archivo a su dispositivo

### ❌ NO PUEDE (Sin `crear:documento`, `editar:documento`, `eliminar:documento`)

1. **NO puede subir nuevos documentos**
   - El botón "+ Subir Documento" **NO aparece** en el módulo principal
   - El botón "+ Subir Documento" **NO aparece** en las fichas de residentes
   - No tiene acceso al modal de subida de documentos

2. **NO puede editar documentos**
   - No puede cambiar la descripción
   - No puede cambiar la categoría
   - No puede reasignar a otra entidad

3. **NO puede eliminar documentos**
   - El botón "Eliminar" (X roja) **NO aparece** en la lista de documentos
   - No puede borrar ningún documento del sistema

## Interfaz Visual del Usuario

### Módulo de Documentación

```
┌─────────────────────────────────────────────┐
│ 📄 Documentación                            │
│                                             │
│ [Limpiar Filtros]                           │  ← Solo botón visible
│                                             │  ← NO hay botón "Subir Documento"
│ ┌────────────────────────────────────────┐ │
│ │ Filtros:                               │ │
│ │ • Residencia: [Todas ▼]                │ │
│ │ • Tipo: [Todos ▼]                      │ │
│ │ • Categoría: [Todas ▼]                 │ │
│ │ • Buscar: [____________]               │ │
│ └────────────────────────────────────────┘ │
│                                             │
│ ┌────────────────────────────────────────┐ │
│ │ 📄 Contrato_Residente_Juan.pdf         │ │
│ │ Residente: Juan Pérez                  │ │
│ │ [👁 Ver] [⬇ Descargar]                │ │  ← Solo botones Ver y Descargar
│ └────────────────────────────────────────┘ │  ← NO hay botón Eliminar
│                                             │
│ ┌────────────────────────────────────────┐ │
│ │ 📄 Factura_Proveedor_123.pdf          │ │
│ │ Proveedor: Suministros SA              │ │
│ │ [👁 Ver] [⬇ Descargar]                │ │
│ └────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

### Comparación: Usuario con Todos los Permisos

```
┌─────────────────────────────────────────────┐
│ 📄 Documentación                            │
│                                             │
│ [+ Subir Documento]  ← ✅ APARECE           │
│ [Limpiar Filtros]                           │
│                                             │
│ [Filtros aquí]                              │
│                                             │
│ ┌────────────────────────────────────────┐ │
│ │ 📄 Contrato_Residente_Juan.pdf         │ │
│ │ [👁 Ver] [⬇ Descargar] [❌ Eliminar]  │ │  ← ✅ Botón Eliminar APARECE
│ └────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

## Protección en Backend

Además de ocultar los botones en el frontend, **el backend TAMBIÉN verifica permisos**:

- Si el usuario intenta subir un documento sin `crear:documento`: **403 Forbidden**
- Si intenta eliminar sin `eliminar:documento`: **403 Forbidden**
- Si intenta editar sin `editar:documento`: **403 Forbidden**

**Doble protección:**
1. 🎨 Frontend: Oculta botones según permisos (mejor UX)
2. 🔒 Backend: Rechaza peticiones no autorizadas (seguridad real)

## Otros Ejemplos de Permisos Granulares

### Ejemplo 1: Usuario que puede ver y crear, pero NO eliminar

```yaml
Permisos:
  - leer:documento ✅
  - crear:documento ✅
  - eliminar:documento ❌

Resultado:
  - Ve el módulo ✅
  - Ve la lista de documentos ✅
  - Puede subir nuevos documentos ✅
  - NO puede eliminar documentos ❌
```

### Ejemplo 2: Usuario que puede todo EXCEPTO crear

```yaml
Permisos:
  - leer:documento ✅
  - editar:documento ✅
  - eliminar:documento ✅
  - crear:documento ❌

Resultado:
  - Ve el módulo ✅
  - Ve la lista de documentos ✅
  - Puede eliminar documentos ✅
  - NO puede subir nuevos documentos ❌
```

### Ejemplo 3: Usuario sin acceso al módulo

```yaml
Permisos:
  - leer:documento ❌

Resultado:
  - El botón "Documentación" NO aparece en el dashboard
  - No puede acceder al módulo de ninguna manera
  - Aunque intente acceder por URL directa, el backend rechaza (403)
```

## Permisos por Módulo

### Residentes
- `leer:residente` → Ver módulo, ver lista, ver fichas
- `crear:residente` → Botón "Agregar Residente"
- `editar:residente` → Editar datos, dar de baja, dar de alta
- `eliminar:residente` → Eliminar completamente

### Facturación
- `leer:cobro` → Ver cobros, ver estimaciones
- `crear:cobro` → Botón "Agregar Cobro"
- `editar:cobro` → Marcar como cobrado, editar cobro
- `eliminar:cobro` → Eliminar cobro
- `leer:pago_proveedor` → Ver pagos a proveedores
- `crear:pago_proveedor` → Botones "Factura Manual", "Procesar Factura"
- `editar:pago_proveedor` → Editar facturas
- `eliminar:pago_proveedor` → Eliminar facturas

### Personal
- `leer:personal` → Ver módulo, ver lista
- `crear:personal` → Botón "Agregar Personal"
- `editar:personal` → Editar datos del personal
- `eliminar:personal` → Eliminar personal

### Documentación
- `leer:documento` → Ver módulo, ver documentos, descargar
- `crear:documento` → Botón "Subir Documento"
- `editar:documento` → Editar descripción, categoría
- `eliminar:documento` → Botón "Eliminar" en documentos

### Históricos
- `leer:registro_asistencial` → Ver módulo de históricos

### Configuración
- `leer:usuario` → Ver usuarios
- `crear:usuario` → Crear nuevos usuarios
- `editar:usuario` → Editar usuarios existentes
- `eliminar:usuario` → Eliminar usuarios
- `leer:residencia` → Ver residencias
- `crear:residencia` → Crear residencias
- `editar:residencia` → Editar residencias

## Rol Especial: Administrador

El rol **Administrador** (id_rol = 2) tiene acceso TOTAL:
- ✅ Todos los permisos de todos los módulos
- ✅ Bypass de todas las restricciones
- ✅ Puede crear otros administradores
- ✅ Puede modificar permisos de cualquier usuario

## Testing de Permisos

Para probar que el sistema funciona correctamente:

1. **Crear usuario de prueba**
   - Rol: Director o Personal
   - Asignar SOLO `leer:documento`
   - NO asignar `crear:documento`, `editar:documento`, `eliminar:documento`

2. **Iniciar sesión con ese usuario**

3. **Verificar comportamiento esperado:**
   - ✅ El botón "Documentación" aparece
   - ✅ Puede acceder al módulo
   - ✅ Ve la lista de documentos
   - ✅ Puede ver y descargar documentos
   - ❌ NO ve el botón "Subir Documento"
   - ❌ NO ve botones "Eliminar" en los documentos

4. **Intentar forzar acceso (opcional):**
   - Abrir consola de desarrollador
   - Intentar llamar `openModal('modalSubirDocumento')`
   - El modal se abre pero el backend rechazará la petición (403)

## Conclusión

El sistema de permisos es **completamente granular y flexible**:

- ✅ Cada acción requiere su permiso específico
- ✅ Un usuario puede tener combinaciones de permisos
- ✅ La UI se adapta automáticamente a los permisos
- ✅ El backend valida SIEMPRE los permisos (seguridad)
- ✅ Fácil de entender y mantener

**Resultado:** Un usuario con solo `leer:documento` puede VER documentos pero NO puede crear, editar o eliminar nada.
