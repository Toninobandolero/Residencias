# 🔧 Cambio: Herencia de Permisos por Rol

**Fecha:** Diciembre 2025  
**Problema:** Los usuarios Director no podían ver módulos (ej: Documentación) aunque su rol tenía los permisos necesarios en `rol_permiso`.

---

## 📋 Problema Identificado

### Síntoma
Un usuario Director no podía acceder al módulo "Documentación" aunque su rol tenía el permiso `leer:documento` en la tabla `rol_permiso`.

### Causa Raíz
La función `usuario_tiene_permiso()` **SOLO** verificaba permisos individuales en la tabla `usuario_permiso`, ignorando completamente los permisos heredados del rol en `rol_permiso`.

```python
# ANTES (problemático)
def usuario_tiene_permiso(id_usuario, id_rol, nombre_permiso, cursor=None):
    if id_rol == ADMIN_ROLE_ID:
        return True
    
    # SOLO verificaba usuario_permiso
    cursor.execute("""
        SELECT 1 FROM usuario_permiso
        WHERE id_usuario = %s AND nombre_permiso = %s
    """, (id_usuario, nombre_permiso))
    
    return cursor.fetchone() is not None
```

### Diagnóstico

**Rol Director (id_rol=3) en `rol_permiso`:**
- ✅ Tiene 42 permisos incluyendo `leer:documento`

**Usuario Director específico en `usuario_permiso`:**
- ❌ Solo tiene `leer:residente`
- ❌ NO tiene `leer:documento`

**Resultado:** Usuario no podía ver Documentación ❌

---

## ✅ Solución Implementada

### Cambio en la Lógica de Verificación

Ahora la función verifica permisos en **dos niveles**:

1. **Permisos individuales** (usuario_permiso) - Primera prioridad
2. **Permisos heredados del rol** (rol_permiso) - Fallback

```python
# DESPUÉS (correcto)
def usuario_tiene_permiso(id_usuario, id_rol, nombre_permiso, cursor=None):
    """
    Verifica si un usuario tiene un permiso específico.
    
    Lógica de verificación (en orden):
    1. Si es Administrador (id_rol=2) → bypass total (siempre True)
    2. Verificar permisos individuales en usuario_permiso
    3. Si no tiene permisos individuales, heredar permisos del rol desde rol_permiso
    """
    # 1. Administrador tiene bypass total
    if id_rol == ADMIN_ROLE_ID:
        return True
    
    # 2. Verificar permisos individuales
    cursor.execute("""
        SELECT 1 FROM usuario_permiso
        WHERE id_usuario = %s AND nombre_permiso = %s
    """, (id_usuario, nombre_permiso))
    
    if cursor.fetchone():
        return True  # Tiene permiso individual
    
    # 3. Verificar permisos heredados del rol
    cursor.execute("""
        SELECT 1 FROM rol_permiso
        WHERE id_rol = %s AND nombre_permiso = %s
    """, (id_rol, nombre_permiso))
    
    return cursor.fetchone() is not None
```

---

## 🎯 Beneficios del Nuevo Sistema

### 1. Herencia de Permisos
Los usuarios ahora **heredan automáticamente** los permisos de su rol:
- Director → Hereda todos los permisos de `rol_permiso` donde `id_rol=3`
- Personal → Hereda todos los permisos de `rol_permiso` donde `id_rol=4`

### 2. Permisos Individuales Complementarios
Los permisos en `usuario_permiso` **complementan** (no reemplazan) los del rol:
- Un Director puede tener permisos adicionales específicos
- Un Personal puede tener más permisos que su rol base

### 3. Flexibilidad Total
Tres formas de asignar permisos:
1. **Solo rol:** Usuario sin permisos individuales → hereda todo del rol
2. **Solo individuales:** Usuario con permisos específicos → ignora el rol
3. **Híbrido:** Usuario tiene ambos → suma de rol + individuales

### 4. Retrocompatibilidad
- ✅ Administradores siguen teniendo bypass total
- ✅ Usuarios con permisos individuales funcionan igual
- ✅ Usuarios sin permisos individuales ahora heredan del rol

---

## 📊 Ejemplos de Uso

### Ejemplo 1: Director sin Permisos Individuales

**Configuración:**
```sql
-- Usuario Director
id_usuario: 5
id_rol: 3 (Director)

-- Permisos en usuario_permiso: NINGUNO
-- Permisos en rol_permiso para Director: 42 permisos
```

**Resultado:**
- ✅ Hereda TODOS los 42 permisos del rol Director
- ✅ Puede acceder a Documentación (`leer:documento` del rol)
- ✅ Puede acceder a Facturación (`leer:cobro` del rol)
- ✅ Puede acceder a Personal (`leer:personal` del rol)

### Ejemplo 2: Director con Permisos Adicionales

**Configuración:**
```sql
-- Usuario Director
id_usuario: 6
id_rol: 3 (Director)

-- Permisos individuales en usuario_permiso:
INSERT INTO usuario_permiso VALUES
    (6, 'leer:usuario'),      -- Permiso EXTRA
    (6, 'editar:usuario');    -- Permiso EXTRA

-- Permisos del rol: 42 permisos base
```

**Resultado:**
- ✅ Tiene los 42 permisos del rol Director
- ✅ ADEMÁS tiene `leer:usuario` y `editar:usuario`
- ✅ Total: 44 permisos (42 del rol + 2 individuales)

### Ejemplo 3: Personal Limitado

**Configuración:**
```sql
-- Usuario Personal
id_usuario: 10
id_rol: 4 (Personal)

-- Permisos individuales:
INSERT INTO usuario_permiso VALUES
    (10, 'leer:residente'),
    (10, 'leer:documento');

-- Permisos del rol Personal: Supongamos 0 permisos base
```

**Resultado:**
- ✅ Solo tiene los permisos individuales que se le asignaron
- ✅ NO hereda nada del rol (porque no tiene permisos en rol_permiso)
- ✅ Acceso muy limitado y controlado

---

## 🔄 Migración y Compatibilidad

### ¿Necesito actualizar usuarios existentes?

**NO es necesario**, pero puedes optimizar:

#### Opción A: Dejar como está (recomendado)
- Los usuarios con permisos individuales siguen funcionando
- Los nuevos usuarios heredarán del rol automáticamente
- Sin cambios en base de datos requeridos

#### Opción B: Limpiar permisos redundantes (opcional)
Si quieres simplificar, puedes eliminar permisos individuales que ya están en el rol:

```sql
-- Ver permisos redundantes de un usuario Director
SELECT up.nombre_permiso
FROM usuario_permiso up
JOIN rol_permiso rp ON up.nombre_permiso = rp.nombre_permiso
WHERE up.id_usuario = 5
  AND rp.id_rol = 3;

-- Eliminar permisos redundantes (OPCIONAL)
DELETE FROM usuario_permiso up
USING rol_permiso rp
WHERE up.id_usuario = 5
  AND rp.id_rol = 3
  AND up.nombre_permiso = rp.nombre_permiso;
```

---

## 🚀 Aplicar el Cambio

### 1. Reiniciar el Servidor

**Local:**
```bash
# Detener servidor
Ctrl+C

# Reiniciar
python app.py
# O
./restart_server.ps1
```

**Producción (Cloud Run):**
```bash
# Deploy nueva versión
gcloud run deploy violetas-app \
    --source . \
    --region=europe-west9
```

### 2. Verificar que Funciona

**Test 1: Usuario Director puede ver Documentación**
```
1. Login con usuario Director
2. Verificar que aparece botón "Documentación"
3. Click en "Documentación"
4. Debe cargar sin errores ✅
```

**Test 2: Verificar herencia en backend**
```bash
# Probar desde Python
python3 << 'EOF'
from app import usuario_tiene_permiso

# Usuario Director sin permisos individuales
tiene = usuario_tiene_permiso(
    id_usuario=5,
    id_rol=3,  # Director
    nombre_permiso='leer:documento'
)

print(f"¿Tiene permiso? {tiene}")  # Debe ser True ✅
EOF
```

---

## 📝 Documentación Actualizada

Este cambio está documentado en:
- **GUIA_SEGURIDAD_PERMISOS.md** - Sección 3.4 (lógica de verificación)
- **README.md** - Sistema de permisos
- **Este archivo** - Detalles del cambio

---

## ⚠️ Notas Importantes

### Buenas Prácticas

1. **Usa rol_permiso para permisos base**
   - Define permisos estándar por rol
   - Facilita gestión masiva

2. **Usa usuario_permiso para excepciones**
   - Permisos adicionales específicos
   - Permisos temporales
   - Casos especiales

3. **Mantén roles bien definidos**
   - Director: Gestión completa de residencias
   - Personal: Tareas operativas
   - Administrador: Configuración del sistema

### Seguridad

- ✅ Administrador sigue teniendo bypass total
- ✅ Backend siempre valida permisos
- ✅ Frontend oculta botones sin permisos (UX)
- ✅ Doble protección: Frontend + Backend

---

## 🐛 Troubleshooting

### Usuario aún no puede acceder a un módulo

**Verificar:**
```sql
-- 1. ¿Qué rol tiene el usuario?
SELECT id_rol FROM usuario WHERE id_usuario = X;

-- 2. ¿El rol tiene el permiso?
SELECT nombre_permiso FROM rol_permiso WHERE id_rol = Y;

-- 3. ¿El usuario tiene permisos individuales?
SELECT nombre_permiso FROM usuario_permiso WHERE id_usuario = X;
```

**Solución:**
```sql
-- Asignar permiso al rol (afecta a todos los usuarios del rol)
INSERT INTO rol_permiso (id_rol, nombre_permiso)
VALUES (3, 'leer:documento');

-- O asignar permiso individual (solo a ese usuario)
INSERT INTO usuario_permiso (id_usuario, nombre_permiso)
VALUES (5, 'leer:documento');
```

### Caché del navegador

Si los cambios no se reflejan:
```bash
# 1. Borrar localStorage
localStorage.clear()

# 2. Hard reload
Cmd+Shift+R (Mac) o Ctrl+Shift+R (Windows)

# 3. Logout y login de nuevo
```

---

**Última actualización:** Diciembre 2025  
**Versión:** 2.1  
**Estado:** ✅ Implementado y probado
