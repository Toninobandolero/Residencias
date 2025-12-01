# 🔐 Guía de Seguridad y Gestión de Usuarios

## 📋 Tabla de Contenidos

1. [Arquitectura de Seguridad](#arquitectura-de-seguridad)
2. [Sistema de Autenticación](#sistema-de-autenticación)
3. [Sistema de Autorización](#sistema-de-autorización)
4. [Super Administrador](#super-administrador)
5. [Gestión de Usuarios](#gestión-de-usuarios)
6. [Roles y Permisos](#roles-y-permisos)
7. [Seguridad de Contraseñas](#seguridad-de-contraseñas)

---

## 🏗️ Arquitectura de Seguridad

### Componentes Principales

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  Frontend   │         │   Backend    │         │  PostgreSQL │
│  (SPA)      │────────▶│   (Flask)    │────────▶│  (Cloud SQL)│
│             │  JWT    │              │         │             │
└─────────────┘         └──────────────┘         └─────────────┘
     :5000                   :5000                      :5432
```

### Flujo de Autenticación

```
1. Usuario → Frontend → POST /api/v1/login
2. Backend verifica credenciales en BD
3. Backend genera token JWT (solo id_usuario e id_rol)
4. Frontend guarda token en localStorage
5. Todas las peticiones incluyen: Authorization: Bearer <token>
6. Backend valida token y carga residencias desde usuario_residencia
7. Backend filtra datos por residencias asignadas (o bypass si super_admin)
```

---

## 🔐 Sistema de Autenticación

### Login

**Endpoint:** `POST /api/v1/login`

**Request:**
```json
{
  "email": "admin@residencias.com",
  "password": "ContraseñaSegura123!"
}
```

**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "requiere_cambio_clave": false
}
```

**Response si requiere cambio de contraseña:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "requiere_cambio_clave": true,
  "mensaje": "Debes cambiar tu contraseña antes de continuar"
}
```

### Estructura del Token JWT

**⚠️ IMPORTANTE:** El token JWT **NO incluye** `id_residencia`. Solo contiene:

```json
{
  "id_usuario": 1,
  "id_rol": 1,
  "exp": 1732896000
}
```

**Motivo:** Los usuarios pueden tener acceso a múltiples residencias. Las residencias se cargan desde la tabla `usuario_residencia` en el middleware.

### Uso del Token

Todas las peticiones protegidas requieren:

```
Authorization: Bearer <token_jwt>
```

### Validación del Token

El middleware `before_request` valida:
1. ✅ Token presente en header `Authorization`
2. ✅ Token válido y no expirado
3. ✅ Payload contiene `id_usuario` e `id_rol`
4. ✅ Carga residencias desde `usuario_residencia` (o bypass si super_admin)
5. ✅ Verifica si requiere cambio de contraseña

### Rate Limiting

El sistema implementa rate limiting para prevenir ataques de fuerza bruta:

- **Máximo 5 intentos** por IP
- **Ventana de tiempo:** 1 minuto
- **Bloqueo temporal:** Después de 5 intentos fallidos

---

## 🛡️ Sistema de Autorización

### Decorador `@permiso_requerido`

Los endpoints protegidos usan el decorador `@permiso_requerido`:

```python
@app.route('/api/v1/residentes', methods=['GET'])
@permiso_requerido('leer:residente')
def listar_residentes():
    # ...
```

**Lógica del decorador:**

1. **Validación JWT** (ya hecho en `before_request`)
2. **Bypass para super_admin:**
   - Si `id_rol == 1` (super_admin), permite acceso inmediatamente
3. **Verificación de permiso:**
   - Consulta tabla `rol_permiso` para verificar si el rol tiene el permiso
   - Si no tiene permiso, retorna `403 Forbidden`
4. **Ejecución del endpoint**

### Filtrado por Residencias

**Para super_admin:**
- ✅ Acceso total (sin filtro)
- ✅ Puede ver todas las residencias

**Para usuarios normales:**
- ✅ Solo ve datos de residencias asignadas
- ✅ Filtro automático: `WHERE id_residencia IN (lista_de_ids)`
- ✅ Lista de residencias en `g.residencias_acceso`

### Helper Functions

**`validate_residencia_access(id_residencia_from_db)`**
- Valida que un recurso pertenezca a una residencia accesible
- Bypass automático para super_admin

**`build_residencia_filter(table_alias, column_name)`**
- Construye cláusula WHERE para filtrar por residencias
- Retorna `(None, None)` para super_admin (sin filtro)

---

## 👑 Super Administrador

### Características

- **Rol ID:** 1 (constante `SUPER_ADMIN_ROLE_ID`)
- **Acceso:** Total a todas las residencias
- **Permisos:** Bypass completo (no verifica permisos)
- **Residencias:** No tiene residencias asignadas (acceso ilimitado)
- **Funciones especiales:**
  - Puede crear usuarios (incluyendo otros super_admin)
  - Puede acceder a cualquier endpoint sin verificar permisos

### Crear Super Administrador

**⚠️ SOLO debe crearse mediante script directo en BD:**

```powershell
python init_database.py
```

**NUNCA** crear super_admin a través de la API.

### Credenciales por Defecto

- **Email:** `admin@residencias.com`
- **Password:** `CambiarContraseña123!`
- ⚠️ **IMPORTANTE:** Debe cambiar la contraseña en el primer login

### Personalizar Credenciales

Agregar al `.env`:

```env
SUPER_ADMIN_EMAIL=tu_email@ejemplo.com
SUPER_ADMIN_PASSWORD=TuContraseñaSegura123!
```

---

## 👥 Gestión de Usuarios

### Crear Usuario (Solo Super Admin)

**Endpoint:** `POST /api/v1/usuarios`

**Request:**
```json
{
  "email": "admin1@violetas.com",
  "password": "ContraseñaSegura123!",
  "id_rol": 2,
  "id_residencias": [1, 2],
  "nombre": "Administrador",
  "apellido": "Violetas"
}
```

**Validaciones:**
- ✅ Email único
- ✅ Contraseña cumple política de seguridad
- ✅ Rol existe
- ✅ Residencias existen y están activas
- ✅ Solo super_admin puede crear usuarios

**Response (201 Created):**
```json
{
  "id_usuario": 2,
  "email": "admin1@violetas.com",
  "id_rol": 2,
  "mensaje": "Usuario creado exitosamente. Requiere cambio de contraseña en primer login."
}
```

### Cambiar Contraseña

**Endpoint:** `POST /api/v1/usuario/cambio-clave`

**Request:**
```json
{
  "clave_actual": "ContraseñaActual123!",
  "clave_nueva": "NuevaContraseña456!"
}
```

**Validaciones:**
- ✅ Contraseña actual correcta
- ✅ Contraseña nueva cumple política de seguridad
- ✅ Contraseña nueva diferente a la actual

**Efecto:**
- ✅ Actualiza `password_hash` en BD
- ✅ Establece `requiere_cambio_clave = FALSE`
- ✅ Usuario puede continuar usando el sistema

### Bloqueo por Cambio de Contraseña

Si `requiere_cambio_clave = TRUE`:

- ❌ **Bloquea acceso** a endpoints sensibles
- ✅ **Permite acceso** a:
  - `POST /api/v1/usuario/cambio-clave`
  - `GET /health`
  - `POST /api/v1/login`

---

## 🎭 Roles y Permisos

### Estructura de Roles

El sistema usa un sistema jerárquico de roles:

```
super_admin (id_rol = 1)
    ├── Acceso total
    ├── Puede crear usuarios
    └── Bypass completo de permisos

Administrador (id_rol = 2)
    ├── Acceso a residencias asignadas
    └── Permisos según configuración

Director (id_rol = 3)
    ├── Acceso a residencias asignadas
    └── Permisos limitados

Personal (id_rol = 4+)
    ├── Acceso a residencias asignadas
    └── Permisos básicos
```

### Sistema de Permisos Granulares (ACL)

**Tablas:**
- `permiso` - Permisos del sistema (ej: `leer:residente`, `escribir:tratamiento`)
- `rol_permiso` - Relación entre roles y permisos
- `usuario_residencia` - Residencias asignadas a cada usuario

**Formato de Permisos:**
- `accion:recurso`
- Ejemplos:
  - `leer:residente`
  - `escribir:tratamiento`
  - `eliminar:pago_proveedor`

### Asignar Residencias a Usuarios

Los usuarios pueden tener acceso a **múltiples residencias** mediante la tabla `usuario_residencia`:

```sql
INSERT INTO usuario_residencia (id_usuario, id_residencia)
VALUES 
    (2, 1),  -- Acceso a Violetas 1
    (2, 2);  -- Acceso a Violetas 2
```

Al hacer login, el sistema carga todas las residencias asignadas en `g.residencias_acceso`.

---

## 🔒 Seguridad de Contraseñas

### Política de Contraseñas

La contraseña debe cumplir:
- ✅ **Mínimo 8 caracteres**
- ✅ **Al menos una mayúscula**
- ✅ **Al menos una minúscula**
- ✅ **Al menos un número**
- ✅ **Al menos un carácter especial** (`!@#$%^&*(),.?":{}|<>`)

### Almacenamiento

- ✅ **Hash:** Werkzeug `scrypt` (algoritmo seguro)
- ✅ **NUNCA** se almacena la contraseña en texto plano
- ✅ **Verificación:** `check_password_hash()` para comparar

### Cambio Obligatorio

- ✅ **Al crear usuario:** `requiere_cambio_clave = TRUE`
- ✅ **Bloqueo de acceso** hasta cambiar contraseña
- ✅ **Solo endpoint de cambio** disponible hasta completar

### Rate Limiting en Login

- ✅ **5 intentos máximos** por IP
- ✅ **Ventana:** 1 minuto
- ✅ **Bloqueo temporal** después de 5 intentos

---

## 🔍 Validaciones de Seguridad

### Middleware `before_request`

Valida en cada petición:
1. ✅ Token JWT válido y no expirado
2. ✅ Usuario tiene residencias asignadas (excepto super_admin)
3. ✅ No requiere cambio de contraseña (excepto endpoints permitidos)
4. ✅ Carga lista de residencias en `g.residencias_acceso`

### Decorador `@permiso_requerido`

Valida:
1. ✅ JWT válido (ya verificado)
2. ✅ Super_admin tiene bypass automático
3. ✅ Rol tiene permiso requerido
4. ✅ Usuario tiene acceso a residencias necesarias

### Validación de Entrada

Todos los endpoints validan:
- ✅ Tipos de datos correctos
- ✅ Rangos válidos
- ✅ Formato de emails
- ✅ Sanitización de datos
- ✅ Prevención de SQL injection (usando parámetros)

---

## 📊 Logs de Seguridad

El sistema registra eventos de seguridad:

- ✅ **Login exitoso**
- ✅ **Login fallido**
- ✅ **Cambio de contraseña**
- ✅ **Intentos de acceso no autorizado**

Ver logs en consola del servidor o archivo de logs.

---

Para más detalles sobre la API, ver `REFERENCIA_API.md`

