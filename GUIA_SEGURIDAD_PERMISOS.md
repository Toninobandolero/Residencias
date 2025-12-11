# 🔒 Guía de Seguridad y Sistema de Permisos

**Sistema de Gestión de Residencias Violetas - Seguridad Completa**

Esta guía cubre toda la arquitectura de seguridad, autenticación, autorización y sistema de permisos del sistema.

---

## 📋 Tabla de Contenidos

1. [Arquitectura de Seguridad](#1-arquitectura-de-seguridad)
2. [Sistema de Autenticación](#2-sistema-de-autenticación)
3. [Roles y Permisos Backend](#3-roles-y-permisos-backend)
4. [Sistema de Permisos Frontend](#4-sistema-de-permisos-frontend)
5. [Ejemplos Prácticos](#5-ejemplos-prácticos)
6. [Seguridad del Repositorio](#6-seguridad-del-repositorio)
7. [Best Practices](#7-best-practices)

---

## 1. Arquitectura de Seguridad

### 1.1. Capas de Seguridad

El sistema implementa seguridad en **múltiples capas**:

```
┌─────────────────────────────────────────┐
│  1. Autenticación (JWT)                 │
│     ↓ ¿Usuario válido?                  │
├─────────────────────────────────────────┤
│  2. Autorización por Permiso (Backend)  │
│     ↓ ¿Tiene permiso específico?        │
├─────────────────────────────────────────┤
│  3. Filtrado por Residencia             │
│     ↓ ¿Acceso a esta residencia?        │
├─────────────────────────────────────────┤
│  4. Control de UI (Frontend)            │
│     ↓ Mostrar/ocultar según permisos    │
└─────────────────────────────────────────┘
```

### 1.2. Principios de Seguridad

✅ **Least Privilege** - Usuarios solo tienen permisos necesarios
✅ **Defense in Depth** - Múltiples capas de seguridad
✅ **Zero Trust** - Verificar siempre, nunca confiar
✅ **Separation of Duties** - Permisos granulares separados
✅ **Audit Trail** - Logs de todas las acciones importantes

---

## 2. Sistema de Autenticación

### 2.1. JWT (JSON Web Tokens)

**Funcionamiento:**

1. Usuario envía email + contraseña
2. Sistema verifica credenciales
3. Si válidas → genera JWT con payload:
   ```json
   {
     "id_usuario": 123,
     "email": "usuario@ejemplo.com",
     "id_rol": 3,
     "id_residencia": 1,
     "exp": 1734567890
   }
   ```
4. Cliente guarda token en `localStorage`
5. Cliente envía token en header: `Authorization: Bearer <token>`

### 2.2. Endpoints de Autenticación

#### Login
```
POST /api/v1/login
Body: { "email": "...", "password": "..." }
Response: { "token": "eyJ...", "usuario": {...} }
```

#### Obtener Usuario Actual
```
GET /api/v1/usuarios/me
Headers: Authorization: Bearer <token>
Response: { "id_usuario": ..., "nombre": ..., "permisos": [...], "residencias": [...] }
```

### 2.3. Contraseñas

**Almacenamiento:**
- Hash con `werkzeug.security.generate_password_hash()`
- Algoritmo: pbkdf2:sha256
- **NUNCA** se almacenan en texto plano

**Validación:**
- Mínimo 8 caracteres
- Al menos 1 may

úscula
- Al menos 1 minúscula  
- Al menos 1 número
- Al menos 1 carácter especial (!@#$%^&*..)

**Ejemplo:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

# Al crear usuario
hashed = generate_password_hash('MiPassword123!')

# Al verificar login
if check_password_hash(hashed, password_ingresado):
    # Login exitoso
```

### 2.4. Expiración de Tokens

- **Duración:** 24 horas
- **Renovación:** Usuario debe hacer login nuevamente
- **Logout:** Cliente elimina token de localStorage

---

## 3. Roles y Permisos Backend

### 3.1. Tabla de Roles

| ID | Nombre | Descripción |
|----|--------|-------------|
| 2 | Administrador | Acceso total al sistema |
| 3 | Director | Gestión de residencia(s) |
| 4 | Personal | Acceso limitado según permisos |

**Nota:** El `id_rol=1` (super_admin) está deprecado. Administrador es el nuevo rol máximo.

### 3.2. Tabla de Permisos

**Estructura:** `accion:recurso`

**Acciones posibles:**
- `leer` - Ver información
- `crear` - Crear nuevos registros
- `editar` - Modificar registros existentes
- `eliminar` - Eliminar registros

**Recursos disponibles:**

| Recurso | Permisos |
|---------|----------|
| **Residentes** | `leer:residente`, `crear:residente`, `editar:residente`, `eliminar:residente` |
| **Personal** | `leer:personal`, `crear:personal`, `editar:personal`, `eliminar:personal` |
| **Cobros** | `leer:cobro`, `crear:cobro`, `editar:cobro`, `eliminar:cobro` |
| **Pagos Proveedores** | `leer:pago_proveedor`, `crear:pago_proveedor`, `editar:pago_proveedor`, `eliminar:pago_proveedor` |
| **Proveedores** | `leer:proveedor`, `crear:proveedor`, `editar:proveedor`, `eliminar:proveedor` |
| **Documentos** | `leer:documento`, `crear:documento`, `editar:documento`, `eliminar:documento` |
| **Históricos** | `leer:registro_asistencial`, `crear:registro_asistencial`, `editar:registro_asistencial` |
| **Usuarios** | `leer:usuario`, `crear:usuario`, `editar:usuario`, `eliminar:usuario` |
| **Residencias** | `leer:residencia`, `crear:residencia`, `editar:residencia` |
| **Turnos Extra** | `leer:turno_extra`, `crear:turno_extra`, `editar:turno_extra`, `eliminar:turno_extra` |

### 3.3. Asignación de Permisos

Los permisos se asignan a nivel de **usuario individual** en la tabla `usuario_permiso`:

```sql
CREATE TABLE usuario_permiso (
    id_usuario INTEGER,
    nombre_permiso VARCHAR(100),
    PRIMARY KEY (id_usuario, nombre_permiso),
    FOREIGN KEY (id_usuario) REFERENCES usuario(id_usuario),
    FOREIGN KEY (nombre_permiso) REFERENCES permiso(nombre)
);
```

**Ejemplo:**
```sql
-- Asignar permisos a un usuario
INSERT INTO usuario_permiso (id_usuario, nombre_permiso) VALUES
    (5, 'leer:residente'),
    (5, 'crear:residente'),
    (5, 'leer:documento');
```

### 3.4. Verificación de Permisos en Backend

**Función principal:**
```python
def usuario_tiene_permiso(id_usuario, nombre_permiso):
    """
    Verifica si un usuario tiene un permiso específico.
    
    REGLA ESPECIAL: Administradores (id_rol=2) tienen TODOS los permisos.
    """
    # 1. Obtener rol del usuario
    usuario = obtener_usuario_por_id(id_usuario)
    
    # 2. Si es Administrador → Acceso total
    if usuario['id_rol'] == 2:  # ADMIN_ROLE_ID
        return True
    
    # 3. Verificar en usuario_permiso
    query = """
        SELECT 1 FROM usuario_permiso
        WHERE id_usuario = %s AND nombre_permiso = %s
    """
    result = cursor.execute(query, (id_usuario, nombre_permiso))
    return result.fetchone() is not None
```

**Decorador para endpoints:**
```python
def permiso_requerido(permiso):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Verificar token JWT
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'error': 'No autenticado'}), 401
            
            # 2. Decodificar token
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
                g.id_usuario = payload['id_usuario']
            except:
                return jsonify({'error': 'Token inválido'}), 401
            
            # 3. Verificar permiso
            if not usuario_tiene_permiso(g.id_usuario, permiso):
                return jsonify({'error': 'Sin permisos'}), 403
            
            # 4. Ejecutar función
            return f(*args, **kwargs)
        return decorated_function
    return decorator
```

**Uso en endpoints:**
```python
@app.route('/api/v1/residentes', methods=['GET'])
@permiso_requerido('leer:residente')
def listar_residentes():
    # Solo ejecuta si usuario tiene permiso 'leer:residente'
    ...

@app.route('/api/v1/residentes', methods=['POST'])
@permiso_requerido('crear:residente')
def crear_residente():
    # Solo ejecuta si usuario tiene permiso 'crear:residente'
    ...
```

### 3.5. Filtrado por Residencia

Además de permisos, los datos se filtran por residencias asignadas:

```python
# Obtener residencias del usuario
residencias_usuario = obtener_residencias_usuario(id_usuario)
# → [1, 2]  # Usuario tiene acceso a residencias 1 y 2

# Filtrar datos
query = """
    SELECT * FROM residente
    WHERE id_residencia IN %s
"""
cursor.execute(query, (tuple(residencias_usuario),))
```

---

## 4. Sistema de Permisos Frontend

### 4.1. Verificación en Frontend

**Función global:**
```javascript
// Variable global con datos del usuario
let usuarioActual = null;

// Función para verificar permisos
function usuarioTienePermiso(nombrePermiso) {
    if (!usuarioActual) return false;
    
    // Administradores tienen todos los permisos
    if (usuarioActual.id_rol === 2) return true;
    
    // Verificar en lista de permisos del usuario
    return usuarioActual.permisos && 
           usuarioActual.permisos.includes(nombrePermiso);
}
```

### 4.2. Funciones Helper para Botones

Para evitar template strings anidados (que causan errores de sintaxis), usamos funciones helper:

#### `botonSiPermiso()` - Para botones estáticos

```javascript
function botonSiPermiso(permiso, config) {
    if (!usuarioTienePermiso(permiso)) return '';
    
    const { texto, onclick, id, estilo, clase = 'add-btn', icono } = config;
    
    const idAttr = id ? `id="${id}"` : '';
    const onclickAttr = onclick ? `onclick="${onclick}"` : '';
    const estiloAttr = estilo ? `style="${estilo}"` : '';
    
    let contenido = texto;
    if (icono) contenido = `${icono} ${texto}`;
    
    return `<button ${idAttr} ${onclickAttr} class="${clase}" ${estiloAttr}>${contenido}</button>`;
}
```

**Uso:**
```javascript
${botonSiPermiso('crear:cobro', {
    texto: '+ Agregar Cobro',
    onclick: "openModal('modalCobro')",
    clase: 'add-btn',
    estilo: 'padding: 8px 16px;'
})}
```

#### `botonConIdSiPermiso()` - Para botones con IDs dinámicos

```javascript
function botonConIdSiPermiso(permiso, config, ...params) {
    if (!usuarioTienePermiso(permiso)) return '';
    
    const { texto, funcionOnclick, idBtn, estilo, clase, icono } = config;
    
    const idAttr = idBtn ? `id="${idBtn}"` : '';
    const paramsStr = params.join(', ');
    const onclickAttr = funcionOnclick ? `onclick="${funcionOnclick}(${paramsStr})"` : '';
    const estiloAttr = estilo ? `style="${estilo}"` : '';
    const claseAttr = clase ? `class="${clase}"` : '';
    
    let contenido = texto;
    if (icono) contenido = icono + ' ' + texto;
    
    return '<button ' + idAttr + ' ' + onclickAttr + ' ' + claseAttr + ' ' + estiloAttr + '>' + contenido + '</button>';
}
```

**Uso:**
```javascript
${botonConIdSiPermiso('editar:residente', {
    texto: 'Editar',
    funcionOnclick: 'editarResidente',
    estilo: 'background: #667eea; color: white;'
}, residente.id_residente)}
```

### 4.3. Visibilidad de Módulos

```javascript
function actualizarVisibilidadModulos() {
    const modulosPermisos = {
        'residentes': 'leer:residente',
        'facturacion': ['leer:cobro', 'leer:pago_proveedor'],  // Al menos uno
        'personal': 'leer:personal',
        'documentacion': 'leer:documento',
        'historicos': 'leer:registro_asistencial',
        'configuracion': ['leer:usuario', 'leer:residencia']
    };

    for (const [modulo, permisoRequerido] of Object.entries(modulosPermisos)) {
        const boton = botonesModulos[modulo];
        if (!boton) continue;

        let tieneAcceso = false;
        if (Array.isArray(permisoRequerido)) {
            // Si es array, necesita al menos uno
            tieneAcceso = permisoRequerido.some(p => usuarioTienePermiso(p));
        } else {
            // Si es string, necesita ese permiso
            tieneAcceso = usuarioTienePermiso(permisoRequerido);
        }

        boton.style.display = tieneAcceso ? 'block' : 'none';
    }
}
```

### 4.4. Reglas de Uso

**✅ HACER:**
1. Usar `botonSiPermiso()` para botones sin IDs dinámicos
2. Usar `botonConIdSiPermiso()` para botones con IDs
3. Separar lógica de generación de HTML
4. Usar concatenación (`+`) en lugar de template strings anidados

**❌ NO HACER:**
1. NUNCA usar template strings anidados con más de 2 niveles
2. NUNCA poner variables dinámicas en template strings anidados
3. NUNCA anidar operadores ternarios en template strings

---

## 5. Ejemplos Prácticos

### 5.1. Usuario Solo Lectura

**Configuración:**
```sql
-- Usuario con solo lectura de documentación
INSERT INTO usuario_permiso (id_usuario, nombre_permiso) VALUES
    (10, 'leer:documento');
```

**Resultado:**
- ✅ Ve el módulo "Documentación"
- ✅ Ve lista de documentos
- ✅ Puede ver y descargar documentos
- ❌ NO ve botón "Subir Documento"
- ❌ NO ve botones "Eliminar"

### 5.2. Director de Una Residencia

**Configuración:**
```sql
-- Asignar permisos de Director
INSERT INTO usuario_permiso (id_usuario, nombre_permiso)
SELECT 5, nombre FROM permiso
WHERE nombre NOT LIKE '%usuario%' 
  AND nombre NOT LIKE '%residencia%';

-- Asignar solo a Residencia 1
INSERT INTO usuario_residencia (id_usuario, id_residencia, activa) VALUES
    (5, 1, true);
```

**Resultado:**
- ✅ Ve todos los módulos EXCEPTO Configuración
- ✅ Puede crear, editar, eliminar en su residencia
- ❌ NO ve datos de otras residencias
- ❌ NO puede gestionar usuarios

### 5.3. Personal de Facturación

**Configuración:**
```sql
-- Solo permisos de facturación
INSERT INTO usuario_permiso (id_usuario, nombre_permiso) VALUES
    (7, 'leer:cobro'),
    (7, 'crear:cobro'),
    (7, 'editar:cobro'),
    (7, 'leer:pago_proveedor'),
    (7, 'crear:pago_proveedor');
```

**Resultado:**
- ✅ Ve solo módulo "Facturación"
- ✅ Puede gestionar cobros y pagos
- ❌ NO ve otros módulos

---

## 6. Seguridad del Repositorio

### 6.1. Archivos Sensibles

**Archivos que NUNCA se versionan:**
- `.env` - Variables de entorno
- `*.json` - Credenciales de GCP
- `*.log` - Logs con posible información sensible
- `__pycache__/` - Cache de Python

**Configuración en `.gitignore`:**
```gitignore
# Variables de entorno
.env
.env.local
.env.production

# Credenciales
*.json
!package.json
!tsconfig.json

# Logs
*.log

# Python
__pycache__/
*.pyc
```

### 6.2. Secrets en Producción

**Usar Google Cloud Secret Manager:**

```bash
# Crear secret
echo -n "valor-secreto" | gcloud secrets create nombre-secret --data-file=-

# Dar acceso a Cloud Run
gcloud secrets add-iam-policy-binding nombre-secret \
    --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

**Acceder en Cloud Run:**
```python
from google.cloud import secretmanager

client = secretmanager.SecretManagerServiceClient()
name = f"projects/{PROJECT_ID}/secrets/{SECRET_NAME}/versions/latest"
response = client.access_secret_version(request={"name": name})
secret_value = response.payload.data.decode('UTF-8')
```

### 6.3. Best Practices

✅ **Rotación de Contraseñas:** Cambiar cada 90 días
✅ **Tokens Limitados:** Expiración de 24 horas
✅ **HTTPS Obligatorio:** En producción
✅ **Validación de Entrada:** Siempre validar datos del usuario
✅ **Logs de Auditoría:** Registrar acciones importantes
✅ **Backups Regulares:** Diarios automáticos

---

## 7. Best Practices

### 7.1. Principio de Menor Privilegio

**Siempre dar el mínimo de permisos necesarios:**

```python
# ❌ MAL - Dar todos los permisos
permisos = ['leer:*', 'crear:*', 'editar:*', 'eliminar:*']

# ✅ BIEN - Solo los necesarios
permisos = ['leer:residente', 'leer:documento']
```

### 7.2. Validación en Ambos Lados

**Frontend Y Backend deben validar:**

```javascript
// Frontend - Mejora UX
if (!usuarioTienePermiso('crear:residente')) {
    alert('Sin permisos');
    return;
}
```

```python
# Backend - Seguridad real
@permiso_requerido('crear:residente')
def crear_residente():
    # ...
```

### 7.3. Auditoría y Logs

**Registrar acciones importantes:**

```python
import logging

@permiso_requerido('eliminar:residente')
def eliminar_residente(id_residente):
    logging.info(f"Usuario {g.id_usuario} eliminó residente {id_residente}")
    # ...
```

### 7.4. Revisión Regular de Permisos

- Revisar permisos cada trimestre
- Eliminar usuarios inactivos
- Verificar accesos innecesarios
- Actualizar documentación

---

## 📞 Soporte y Referencias

**Documentación relacionada:**
- [GUIA_COMPLETA.md](GUIA_COMPLETA.md) - Instalación y configuración
- [REFERENCIA_API.md](REFERENCIA_API.md) - Referencia de API
- [GUIA_TROUBLESHOOTING.md](GUIA_TROUBLESHOOTING.md) - Solución de problemas

**Última actualización:** Diciembre 2025
**Versión:** 2.0
