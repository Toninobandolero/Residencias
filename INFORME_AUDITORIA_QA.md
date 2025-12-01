# 🔍 INFORME DE AUDITORÍA QA - Backend MVP Gestión de Residencias

**Fecha:** $(date +%Y-%m-%d)  
**Auditor:** QA Engineer  
**Proyecto:** Sistema de Gestión de Residencias Violetas  
**Stack:** Flask + PostgreSQL (Cloud SQL)

---

## 📋 RESUMEN EJECUTIVO

### Estado General: ⚠️ **REQUIERE CORRECCIONES CRÍTICAS**

**Puntuación Global:** 6.5/10

| Categoría | Estado | Prioridad |
|-----------|--------|-----------|
| 🛡️ Seguridad y Autenticación | ✅ **APROBADO** | Alta |
| 🔒 Filtrado por Residencia | ⚠️ **PARCIAL** | **CRÍTICA** |
| 💾 Modelo de Datos | ⚠️ **INCOMPLETO** | Alta |
| 🧪 Funcionalidades Críticas | ❌ **FALTANTES** | **CRÍTICA** |

---

## 1️⃣ AUDITORÍA DE SEGURIDAD Y ARQUITECTURA

### 1.1 ✅ Verificación de Login (AuthN)

**Estado:** **APROBADO**

**Implementación encontrada:**

```118:183:app.py
@app.route('/api/v1/login', methods=['POST'])
def login():
    """
    Endpoint de autenticación.
    
    Recibe:
    {
        "email": "usuario@ejemplo.com",
        "password": "contraseña"
    }
    
    Retorna:
    {
        "token": "jwt_token_here"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email y contraseña son requeridos'}), 400
        
        # Conectar a la base de datos
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Buscar usuario por email
            cursor.execute(
                "SELECT id_usuario, email, password_hash, id_rol, id_residencia FROM usuario WHERE email = %s",
                (email,)
            )
            usuario = cursor.fetchone()
            
            if not usuario:
                return jsonify({'error': 'Credenciales inválidas'}), 401
            
            id_usuario, email_db, password_hash, id_rol, id_residencia = usuario
            
            # Verificar contraseña
            if not check_password_hash(password_hash, password):
                return jsonify({'error': 'Credenciales inválidas'}), 401
            
            # Generar token JWT
            payload = {
                'id_usuario': id_usuario,
                'id_rol': id_rol,
                'id_residencia': id_residencia,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }
            
            token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
            
            return jsonify({
                'token': token
            }), 200
            
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        app.logger.error(f"Error en login: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500
```

**Verificaciones:**
- ✅ Usa `check_password_hash` de Werkzeug (línea 164)
- ✅ Genera token JWT con PyJWT (línea 175)
- ✅ Expiración de 24 horas configurada (línea 172)
- ✅ Manejo de errores adecuado

**Recomendaciones:**
- ✅ Implementación correcta
- ⚠️ Considerar rate limiting para prevenir ataques de fuerza bruta

---

### 1.2 ✅ Verificación del Token JWT (AuthZ)

**Estado:** **APROBADO**

**Implementación encontrada:**

```51:90:app.py
@app.before_request
def before_request():
    """
    Middleware que aplica autenticación a todas las rutas excepto las públicas.
    Valida el token JWT y almacena id_residencia e id_usuario en g.
    """
    # Rutas públicas que no requieren autenticación
    public_paths = ['/api/v1/login', '/health', '/']
    # Excluir archivos estáticos y favicon
    if request.path in public_paths or request.path.startswith('/static/') or request.path == '/favicon.ico':
        return None
    
    # Obtener token del header Authorization
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Token de autenticación requerido'}), 401
    
    # Verificar formato Bearer
    try:
        token = auth_header.split(' ')[1]  # "Bearer <token>"
    except IndexError:
        return jsonify({'error': 'Formato de token inválido. Use: Bearer <token>'}), 401
    
    # Validar y decodificar token
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        # Almacenar información del usuario en g para uso en las rutas
        g.id_usuario = payload.get('id_usuario')
        g.id_rol = payload.get('id_rol')
        g.id_residencia = payload.get('id_residencia')
        
        # Validar que los campos requeridos estén presentes
        if not all([g.id_usuario, g.id_rol, g.id_residencia]):
            return jsonify({'error': 'Token inválido: faltan campos requeridos'}), 401
            
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Token inválido'}), 401
    
    return None
```

**Verificaciones:**
- ✅ Token JWT contiene `id_usuario` (línea 78)
- ✅ Token JWT contiene `id_rol` (línea 79)
- ✅ Token JWT contiene `id_residencia` (línea 80)
- ✅ Validación de campos requeridos (línea 83)
- ✅ Manejo de tokens expirados e inválidos

**Recomendaciones:**
- ✅ Implementación correcta

---

### 1.3 ⚠️ Verificación del Filtro Crítico por `id_residencia`

**Estado:** **PARCIALMENTE IMPLEMENTADO - REQUIERE CORRECCIONES CRÍTICAS**

**Problema Identificado:**

No existe una función middleware o decorador centralizado que **fuerce automáticamente** el filtro `WHERE id_residencia = g.id_residencia` en todas las consultas. La verificación se hace de forma **manual** en cada endpoint, lo que es propenso a errores.

**Análisis de Implementación Actual:**

#### ✅ Endpoints que SÍ implementan el filtro correctamente:

1. **Listar Residentes** (línea 340-341):
```340:341:app.py
            if g.id_rol != 1:
                query += f" WHERE r.id_residencia = {g.id_residencia}"
```
⚠️ **PROBLEMA:** Admins (rol 1) pueden ver TODAS las residencias sin restricción.

2. **Turnos Extra** - Todos los endpoints filtran correctamente (líneas 2649, 2721, 2780, etc.)

3. **Pagos de Residentes** - Filtrado implementado (línea 1042, etc.)

#### ❌ **VULNERABILIDAD CRÍTICA** - Endpoints sin validación adecuada:

**1. Obtener Residente Específico** (línea 408-544):

```481:492:app.py
            query = f"""
                SELECT r.id_residente, r.id_residencia, r.nombre, r.apellido, r.documento_identidad,
                       r.fecha_nacimiento, r.telefono, r.direccion, r.contacto_emergencia,
                       r.telefono_emergencia, r.activo, r.fecha_ingreso, r.habitacion,
                       r.costo_habitacion, r.servicios_extra, r.medicaciones, r.peculiaridades, 
                       r.metodo_pago_preferido, r.fecha_creacion
                       {campos_opcionales_str}
                FROM residente r
                WHERE r.id_residente = %s
            """
            
            cursor.execute(query, (id_residente,))
            
            res = cursor.fetchone()
            
            if not res:
                return jsonify({'error': 'Residente no encontrado'}), 404
```

**⚠️ PROBLEMA CRÍTICO:** Este endpoint NO valida que `res[1]` (id_residencia del residente) coincida con `g.id_residencia`. Un usuario de Violetas 1 podría acceder a datos de Violetas 2 si conoce el `id_residente`.

**Solución Requerida:**
```python
# Después de cursor.execute(query, (id_residente,))
res = cursor.fetchone()
if not res:
    return jsonify({'error': 'Residente no encontrado'}), 404

# VERIFICAR QUE EL RESIDENTE PERTENECE A LA RESIDENCIA DEL USUARIO
if g.id_rol != 1 and res[1] != g.id_residencia:  # res[1] es id_residencia
    return jsonify({'error': 'No tienes permisos para acceder a este residente'}), 403
```

#### **Resumen de Vulnerabilidades:**

| Endpoint | Línea | Problema | Severidad |
|----------|-------|----------|-----------|
| `GET /api/v1/residentes/<id>` | 492 | No valida `id_residencia` después de obtener | 🔴 **CRÍTICA** |
| `GET /api/v1/residentes` | 340 | Admins ven todas las residencias | ⚠️ **MEDIA** (si es intencional, documentar) |

**Recomendación Crítica:**

Implementar un decorador o función helper que valide automáticamente el acceso:

```python
def validate_residencia_access(id_residencia_from_db):
    """
    Valida que el id_residencia obtenido de la BD coincida con el del token.
    Excepto para admins (rol 1).
    """
    if g.id_rol != 1 and id_residencia_from_db != g.id_residencia:
        return False
    return True
```

---

## 2️⃣ AUDITORÍA DEL MODELO DE DATOS (PostgreSQL)

### 2.1 ⚠️ Integridad de Esquema

**Estado:** **PARCIALMENTE COMPLETO**

**Tablas Verificadas en `create_schema.sql`:**

#### ✅ Tablas Existentes (9 de 12 esperadas):

1. ✅ `residencia` - snake_case ✓
2. ✅ `rol` - snake_case ✓
3. ✅ `usuario` - snake_case ✓
4. ✅ `residente` - snake_case ✓
5. ✅ `personal` - snake_case ✓
6. ✅ `pago_residente` - snake_case ✓
7. ✅ `pago_proveedor` - snake_case ✓
8. ✅ `turno_normal` - snake_case ✓
9. ✅ `turno_extra` - snake_case ✓
10. ✅ `registro_asistencial` - snake_case ✓

#### ❌ **TABLAS FALTANTES** (2 de 12 esperadas):

Según los requisitos mencionados, deberían existir:

1. ❌ `plantilla_turno` - **NO ENCONTRADA** en el esquema
2. ❌ `medicamento` - **NO ENCONTRADA** en el esquema
3. ❌ `tratamiento` - **NO ENCONTRADA** en el esquema
4. ❌ `administracion_med` - **NO ENCONTRADA** en el esquema

**Nota:** La tabla `factura_residente` mencionada en los requisitos probablemente corresponde a `pago_residente` (ya existe).

#### 📊 Resumen de Tablas:

| Tabla Requerida | Estado | Nombre en BD |
|-----------------|--------|--------------|
| residencia | ✅ | `residencia` |
| residente | ✅ | `residente` |
| rol | ✅ | `rol` |
| usuario | ✅ | `usuario` |
| factura_residente | ✅ | `pago_residente` (sinónimo) |
| pago_residente | ✅ | `pago_residente` |
| pago_proveedor | ✅ | `pago_proveedor` |
| personal | ✅ | `personal` |
| plantilla_turno | ❌ | **FALTANTE** |
| turno_normal | ✅ | `turno_normal` |
| turno_extra | ✅ | `turno_extra` |
| registro_asistencial | ✅ | `registro_asistencial` |
| medicamento | ❌ | **FALTANTE** |
| tratamiento | ❌ | **FALTANTE** |
| administracion_med | ❌ | **FALTANTE** |

**Total:** 9 tablas implementadas, 4 tablas faltantes (módulo médico completo)

---

### 2.2 ✅ Claves Foráneas (FK)

**Estado:** **CORRECTAMENTE IMPLEMENTADAS**

**Verificación de FKs en `create_schema.sql`:**

#### ✅ FKs Verificadas:

1. **usuario:**
   - ✅ `FOREIGN KEY (id_rol) REFERENCES rol(id_rol)` (línea 33)
   - ✅ `FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)` (línea 34)

2. **residente:**
   - ✅ `FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)` (línea 52)

3. **personal:**
   - ✅ `FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)` (línea 68)

4. **pago_residente:**
   - ✅ `FOREIGN KEY (id_residente) REFERENCES residente(id_residente)` (línea 83)
   - ✅ `FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)` (línea 84)

5. **pago_proveedor:**
   - ✅ `FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)` (línea 99)

6. **turno_normal:**
   - ✅ `FOREIGN KEY (id_personal) REFERENCES personal(id_personal)` (línea 113)
   - ✅ `FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)` (línea 114)

7. **turno_extra:**
   - ✅ `FOREIGN KEY (id_personal) REFERENCES personal(id_personal)` (línea 128)
   - ✅ `FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)` (línea 129)

8. **registro_asistencial:**
   - ✅ `FOREIGN KEY (id_residente) REFERENCES residente(id_residente)` (línea 144)
   - ✅ `FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)` (línea 145)
   - ✅ `FOREIGN KEY (id_usuario_registro) REFERENCES usuario(id_usuario)` (línea 146)

**Recomendaciones:**
- ✅ Todas las FKs están correctamente definidas
- ✅ Índices creados para mejorar rendimiento (líneas 150-158)

---

## 3️⃣ AUDITORÍA DE FUNCIONALIDADES CRÍTICAS

### 3.1 ❌ Test de Fichaje (Entrada/Salida)

**Estado:** **NO IMPLEMENTADO**

**Endpoint Esperado:** `/api/v1/fichar/entrada` o similar

**Búsqueda Realizada:**
- ❌ No se encontró ningún endpoint con patrón `/api/v1/fichar/*`
- ❌ No se encontró lógica de fichaje de entrada/salida
- ✅ Existe la tabla `turno_normal` en el esquema (línea 103-115 de `create_schema.sql`)

**Estructura de Tabla `turno_normal`:**
```sql
CREATE TABLE IF NOT EXISTS turno_normal (
    id_turno SERIAL PRIMARY KEY,
    id_personal INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    fecha DATE NOT NULL,
    hora_entrada TIME NOT NULL,
    hora_salida TIME NOT NULL,
    tipo_turno VARCHAR(50),
    observaciones TEXT,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_personal) REFERENCES personal(id_personal),
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);
```

**Recomendación:**

Implementar endpoints de fichaje:

```python
@app.route('/api/v1/fichar/entrada', methods=['POST'])
def fichar_entrada():
    """
    Registra la entrada (fichaje) de un personal.
    Inserta registro en turno_normal con hora_entrada.
    """
    # Validar que id_personal pertenece a g.id_residencia
    # Insertar en turno_normal con fecha actual y hora_entrada
    # Si ya existe un turno sin hora_salida, devolver error
    pass

@app.route('/api/v1/fichar/salida', methods=['POST'])
def fichar_salida():
    """
    Registra la salida (fichaje) de un personal.
    Actualiza el turno_normal con hora_salida.
    """
    # Validar que existe un turno sin hora_salida
    # Actualizar con hora_salida y validar que pertenece a g.id_residencia
    pass
```

---

### 3.2 ❌ Test de Planificación de Turnos Recurrentes

**Estado:** **NO IMPLEMENTADO**

**Endpoint Esperado:** `/api/v1/turnos/plantilla` o similar

**Búsqueda Realizada:**
- ❌ No se encontró ningún endpoint con patrón `*plantilla*`
- ❌ No se encontró la tabla `plantilla_turno` en el esquema
- ✅ Existen endpoints para `turno_extra` pero NO para plantillas

**Endpoints de Turnos Existentes:**
- ✅ `GET /api/v1/turnos-extra` - Listar turnos extra
- ✅ `POST /api/v1/turnos-extra` - Crear turno extra
- ✅ `PUT /api/v1/turnos-extra/<id>` - Actualizar turno extra
- ✅ `DELETE /api/v1/turnos-extra/<id>` - Eliminar turno extra

**Recomendación:**

1. **Crear tabla `plantilla_turno`:**
```sql
CREATE TABLE IF NOT EXISTS plantilla_turno (
    id_plantilla SERIAL PRIMARY KEY,
    id_personal INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    dia_semana INTEGER NOT NULL,  -- 1=Lunes, 7=Domingo
    hora_entrada TIME NOT NULL,
    hora_salida TIME NOT NULL,
    tipo_turno VARCHAR(50),
    activa BOOLEAN DEFAULT TRUE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_personal) REFERENCES personal(id_personal),
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);
```

2. **Implementar endpoints:**
```python
@app.route('/api/v1/turnos/plantilla', methods=['POST'])
def crear_plantilla_turno():
    """
    Crea una plantilla de turno recurrente.
    Inserta en plantilla_turno.
    """
    # Validar que id_personal pertenece a g.id_residencia
    # Insertar en plantilla_turno
    pass

@app.route('/api/v1/turnos/plantilla', methods=['GET'])
def listar_plantillas_turno():
    """
    Lista las plantillas de turnos de la residencia.
    """
    # Filtrar por g.id_residencia
    pass
```

---

## 4️⃣ RESUMEN DE HALLAZGOS Y RECOMENDACIONES

### ✅ **ASPECTOS POSITIVOS:**

1. ✅ Login implementado correctamente con Werkzeug y JWT
2. ✅ Token JWT contiene todos los campos requeridos
3. ✅ Middleware de autenticación funciona correctamente
4. ✅ FKs correctamente definidas en el esquema
5. ✅ Nomenclatura snake_case respetada
6. ✅ La mayoría de endpoints implementan filtrado por `id_residencia`

### 🔴 **VULNERABILIDADES CRÍTICAS:**

1. **🔴 CRÍTICA:** Endpoint `GET /api/v1/residentes/<id>` permite acceso a residentes de otras residencias sin validación
2. **🔴 CRÍTICA:** No existe decorador/middleware centralizado para forzar filtrado por `id_residencia`

### ⚠️ **FUNCIONALIDADES FALTANTES:**

1. **❌ FALTA:** Endpoint de fichaje de entrada/salida (`/api/v1/fichar/entrada`)
2. **❌ FALTA:** Endpoint de plantilla de turnos (`/api/v1/turnos/plantilla`)
3. **❌ FALTA:** Tabla `plantilla_turno`
4. **❌ FALTA:** Tablas del módulo médico: `medicamento`, `tratamiento`, `administracion_med`

---

## 5️⃣ PLAN DE ACCIÓN PRIORITARIO

### 🔴 **Prioridad CRÍTICA (Implementar Inmediatamente):**

1. **Corregir vulnerabilidad de seguridad en `GET /api/v1/residentes/<id>`:**
   - Agregar validación después de obtener el residente (línea 492)
   - Verificar que `res[1] == g.id_residencia` (excepto admins)

2. **Implementar helper function para validación de acceso:**
   ```python
   def validate_residencia_access(id_residencia_from_db):
       if g.id_rol != 1 and id_residencia_from_db != g.id_residencia:
           raise PermissionError("Acceso denegado a esta residencia")
   ```

### 🟠 **Prioridad ALTA (Implementar en Siguiente Sprint):**

3. **Implementar endpoint de fichaje:**
   - `POST /api/v1/fichar/entrada`
   - `POST /api/v1/fichar/salida`

4. **Implementar plantilla de turnos:**
   - Crear tabla `plantilla_turno`
   - `POST /api/v1/turnos/plantilla`
   - `GET /api/v1/turnos/plantilla`

### 🟡 **Prioridad MEDIA (Planificar para Futuras Versiones):**

5. **Implementar módulo médico completo:**
   - Tablas: `medicamento`, `tratamiento`, `administracion_med`
   - Endpoints CRUD correspondientes

---

## 6️⃣ CONCLUSIÓN

El backend del MVP presenta una **base sólida** en autenticación y arquitectura, pero requiere **correcciones críticas de seguridad** antes de ser desplegado en producción.

**Estado Final:** ⚠️ **NO APROBADO PARA PRODUCCIÓN** - Requiere correcciones críticas.

**Tiempo Estimado de Correcciones:**
- Vulnerabilidades críticas: **2-4 horas**
- Funcionalidades faltantes: **1-2 días**

---

**Firma del Auditor QA:**  
_Generado automáticamente por sistema de auditoría_
