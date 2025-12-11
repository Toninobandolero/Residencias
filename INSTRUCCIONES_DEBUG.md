# 🔍 Instrucciones para Debugging del Problema de Edición de Usuarios

## Problema Reportado
Al editar usuarios como Administrador:
- ❌ El rol no se guarda
- ❌ Las residencias no se muestran/guardan correctamente

## Verificación en Base de Datos
✅ Los datos SÍ están correctamente guardados en la BD:
```
Usuario: papaoso@residencias.com
Rol: 3 (Director)
Residencias: [1, 2]
```

Por lo tanto, el problema está en la **carga** o **actualización** a través de la interfaz.

---

## Pasos para Debugging

### 1. Reiniciar el Servidor
```bash
./restart_server.ps1
```

### 2. Abrir Consola del Navegador
- Presiona `F12`
- Ve a la pestaña "Console"

### 3. Editar un Usuario
1. Login como Administrador
2. Ir a Configuración → Usuarios
3. Click en "Editar" en cualquier usuario (ej: papaoso@residencias.com)

### 4. Observar Logs en Consola del Navegador

Deberías ver algo como:

```
🔍 EDITANDO USUARIO ID: 5
🔍 Usuario encontrado: {id_usuario: 5, email: "papaoso@...", id_rol: 3, residencias: [...], permisos: [...]}
🔍 Estableciendo rol a: 3
🔍 Valor del select después de establecer: "3"
🔍 Cargando residencias: [{id_residencia: 1, nombre: "Las Violetas 1"}, {id_residencia: 2, nombre: "Las Violetas 2"}]
🔍 loadResidenciasForSelect llamada con: [...]
🔍 Residencias activas disponibles: [...]
🔍 Residencias a marcar: [...]
🔍 Residencia 1 (Las Violetas 1): MARCADA
🔍 Residencia 2 (Las Violetas 2): MARCADA
🔍 Cargando permisos: [...]
```

**COPIA ESTOS LOGS COMPLETOS**

### 5. Hacer un Cambio y Guardar
1. Cambia algo (ej: deselecciona una residencia o cambia el rol)
2. Click en "Guardar"

### 6. Observar Logs al Guardar

En la consola del navegador verás:

```
🔍 GUARDANDO USUARIO: {
  method: "PUT",
  url: "http://localhost:5001/api/v1/usuarios/5",
  data: {
    email: "papaoso@...",
    id_rol: 4,  // ← Verifica que este valor es correcto
    residencias: [1],  // ← Verifica que estos valores son correctos
    permisos: [...],
    activo: true
  }
}
```

**COPIA ESTE LOG COMPLETO**

### 7. Observar Logs en el Terminal del Servidor

En la terminal donde corre el servidor verás:

```
🔍 ACTUALIZANDO USUARIO 5
🔍 Datos recibidos: {'email': 'papaoso@...', 'id_rol': 4, 'residencias': [1], 'permisos': [...], 'activo': True}
🔍 Updates a aplicar: ['id_rol = %s', 'activo = %s']
🔍 Params: [4, True]
🔍 Query UPDATE: UPDATE usuario SET id_rol = %s, activo = %s WHERE id_usuario = %s
✅ Usuario 5 actualizado exitosamente
```

**COPIA ESTOS LOGS COMPLETOS**

---

## Información a Compartir

Por favor comparte:

### A. Logs del Navegador (Consola F12)

**Al abrir el modal de edición:**
```
[Pega aquí los logs de 🔍 EDITANDO USUARIO ID hasta el final]
```

**Al guardar:**
```
[Pega aquí los logs de 🔍 GUARDANDO USUARIO]
```

### B. Logs del Servidor (Terminal)

```
[Pega aquí los logs de 🔍 ACTUALIZANDO USUARIO hasta ✅]
```

### C. Comportamiento Observado

1. ¿Qué valor tiene el select de Rol cuando abres el modal?
2. ¿Qué residencias aparecen marcadas cuando abres el modal?
3. ¿Qué cambios haces?
4. ¿Qué valores esperabas que se guardaran?
5. Después de guardar y recargar, ¿qué valores ves?

---

## Posibles Causas Identificadas

### Causa 1: Select de Rol No Se Establece Correctamente
**Síntoma:** El select aparece vacío o con valor incorrecto al abrir el modal

**Solución:** Ya implementada - se carga `loadRolesForSelect()` ANTES de establecer el valor

### Causa 2: Residencias No Se Marcan Correctamente
**Síntoma:** No aparecen marcadas las residencias correctas

**Verificar en logs:**
- `usuario.residencias` debe ser un array `[{id_residencia: 1, nombre: "..."}, ...]`
- Los logs de `loadResidenciasForSelect` deben mostrar las residencias que se marcan

### Causa 3: Datos No Se Envían al Backend
**Síntoma:** El payload enviado está vacío o incorrecto

**Verificar en logs:**
- `data` en el log de `🔍 GUARDANDO USUARIO` debe contener todos los campos
- `id_rol` debe ser un número
- `residencias` debe ser un array de números

### Causa 4: Backend No Actualiza Correctamente
**Síntoma:** El servidor recibe datos pero no los guarda

**Verificar en logs:**
- `🔍 Updates a aplicar` debe contener los campos que se van a actualizar
- `✅ Usuario X actualizado exitosamente` debe aparecer

---

## Acciones Inmediatas

✅ Ya realizadas:
- Logs agregados en frontend (`editarUsuario`, `saveUsuario`, `loadResidenciasForSelect`)
- Logs agregados en backend (`actualizar_usuario`)
- Verificación de BD confirmó que datos están guardados

⏳ Pendientes (requieren tu input):
- Ejecutar el flujo de edición con logs activos
- Compartir los logs completos
- Identificar dónde exactamente falla el flujo

---

**Última actualización:** Diciembre 2025  
**Estado:** Esperando logs del usuario para diagnóstico preciso
