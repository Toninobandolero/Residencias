# Adiciones al Plan: Gestión de Usuarios y Seguridad de Contraseñas

## Objetivo Adicional
Implementar sistema completo de gestión de usuarios con creación segura del primer super_admin y cambio obligatorio de contraseña en primer login.

---

## Sección 9: Migración del Esquema de Usuario

### 9.1 Agregar Campo `requiere_cambio_clave` a Tabla Usuario

**Archivo:** Crear nuevo archivo SQL o actualizar `create_schema.sql`

**Script de Migración:**
```sql
-- Agregar campo requiere_cambio_clave a tabla usuario
ALTER TABLE usuario 
ADD COLUMN IF NOT EXISTS requiere_cambio_clave BOOLEAN DEFAULT TRUE;

-- Actualizar usuarios existentes para que requieran cambio de clave
UPDATE usuario SET requiere_cambio_clave = TRUE WHERE requiere_cambio_clave IS NULL;
```

### 9.2 Eliminar Columna `id_residencia` de Tabla Usuario

**Script de Migración:**
```sql
-- Eliminar columna id_residencia de usuario (ahora se usa usuario_residencia)
ALTER TABLE usuario 
DROP COLUMN IF EXISTS id_residencia;
```

---

## Sección 10: Script de Inicialización de Base de Datos

### 10.1 Crear Script `init_database.py`

**Archivo:** Nuevo archivo `init_database.py`

**Contenido:**
```python
"""
Script de inicialización de base de datos.
Crea el primer usuario super_admin directamente en la BD.
NUNCA se debe crear a través de la API.
"""
from werkzeug.security import generate_password_hash
from db_connector import get_db_connection
import os

def init_super_admin():
    """
    Crea el primer usuario super_admin en la base de datos.
    Solo debe ejecutarse una vez durante la inicialización.
    """
    # Email y contraseña del super_admin inicial
    SUPER_ADMIN_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'admin@residencias.com')
    SUPER_ADMIN_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', 'CambiarContraseña123!')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verificar si ya existe el super_admin
        cursor.execute(
            "SELECT id_usuario FROM usuario WHERE id_rol = 1 AND email = %s",
            (SUPER_ADMIN_EMAIL,)
        )
        if cursor.fetchone():
            print(f"El super_admin {SUPER_ADMIN_EMAIL} ya existe. No se creará duplicado.")
            return
        
        # Generar hash de la contraseña
        password_hash = generate_password_hash(SUPER_ADMIN_PASSWORD)
        
        # Insertar el super_admin
        cursor.execute("""
            INSERT INTO usuario (email, password_hash, id_rol, requiere_cambio_clave)
            VALUES (%s, %s, 1, TRUE)
            RETURNING id_usuario
        """, (SUPER_ADMIN_EMAIL, password_hash))
        
        id_usuario = cursor.fetchone()[0]
        conn.commit()
        
        print("="*50)
        print("SUPER ADMIN CREADO EXITOSAMENTE")
        print("="*50)
        print(f"Email: {SUPER_ADMIN_EMAIL}")
        print(f"ID Usuario: {id_usuario}")
        print(f"Rol: Super Administrador (id_rol = 1)")
        print(f"IMPORTANTE: Requiere cambio de contraseña en primer login")
        print("="*50)
        
    except Exception as e:
        conn.rollback()
        print(f"Error al crear super_admin: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    init_super_admin()
```

### 10.2 Actualizar `create_schema.sql`

**Archivo:** [create_schema.sql](create_schema.sql)
**Ubicación:** Después de la creación de tabla usuario (después de línea 35)

**Agregar:**
```sql
-- NOTA: El primer super_admin se crea mediante init_database.py
-- NO se inserta aquí para evitar exponer contraseñas en scripts SQL
```

---

## Sección 11: Actualizar Endpoint de Login

### 11.1 Agregar Verificación de `requiere_cambio_clave`

**Archivo:** [app.py](app.py)
**Ubicación:** Función `login()` (después de línea 184)

**Cambios:**
1. Incluir `requiere_cambio_clave` en la consulta SQL
2. Verificar el flag después de validar contraseña
3. Si `requiere_cambio_clave = TRUE`, retornar código especial (ej: 200 con flag)

```python
# Línea 172: Actualizar consulta SQL
cursor.execute(
    "SELECT id_usuario, email, password_hash, id_rol, requiere_cambio_clave FROM usuario WHERE email = %s",
    (email,)
)

# Línea 181: Desempacar con nuevo campo
id_usuario, email_db, password_hash, id_rol, requiere_cambio_clave = usuario

# Después de línea 184 (verificar contraseña):
# Verificar si requiere cambio de contraseña
if requiere_cambio_clave:
    # Generar token JWT normal
    payload = {
        'id_usuario': id_usuario,
        'id_rol': id_rol,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
    
    return jsonify({
        'token': token,
        'requiere_cambio_clave': True,
        'mensaje': 'Debes cambiar tu contraseña antes de continuar'
    }), 200
```

---

## Sección 12: Endpoint de Cambio de Contraseña

### 12.1 Implementar `POST /api/v1/usuario/cambio-clave`

**Archivo:** [app.py](app.py)
**Ubicación:** Después del endpoint de login (después de línea 210)

**Implementación:**
```python
@app.route('/api/v1/usuario/cambio-clave', methods=['POST'])
def cambiar_clave():
    """
    Endpoint para cambiar la contraseña del usuario autenticado.
    Requiere la contraseña anterior para verificación.
    
    Request:
    {
        "password_actual": "contraseña_actual",
        "password_nuevo": "nueva_contraseña_segura"
    }
    
    Response:
    {
        "mensaje": "Contraseña actualizada exitosamente"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        password_actual = data.get('password_actual')
        password_nuevo = data.get('password_nuevo')
        
        if not password_actual or not password_nuevo:
            return jsonify({'error': 'Contraseña actual y nueva contraseña son requeridas'}), 400
        
        # Validar que la nueva contraseña tenga mínimo de seguridad
        if len(password_nuevo) < 8:
            return jsonify({'error': 'La nueva contraseña debe tener al menos 8 caracteres'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Obtener usuario actual
            cursor.execute(
                "SELECT id_usuario, password_hash FROM usuario WHERE id_usuario = %s",
                (g.id_usuario,)
            )
            usuario = cursor.fetchone()
            
            if not usuario:
                return jsonify({'error': 'Usuario no encontrado'}), 404
            
            id_usuario, password_hash_actual = usuario
            
            # Verificar contraseña actual
            if not check_password_hash(password_hash_actual, password_actual):
                return jsonify({'error': 'Contraseña actual incorrecta'}), 401
            
            # Hashear nueva contraseña
            password_hash_nuevo = generate_password_hash(password_nuevo)
            
            # Actualizar contraseña y marcar que ya no requiere cambio
            cursor.execute("""
                UPDATE usuario
                SET password_hash = %s,
                    requiere_cambio_clave = FALSE
                WHERE id_usuario = %s
                RETURNING id_usuario
            """, (password_hash_nuevo, id_usuario))
            
            conn.commit()
            
            return jsonify({
                'mensaje': 'Contraseña actualizada exitosamente'
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al cambiar contraseña: {str(e)}")
            return jsonify({'error': 'Error al actualizar contraseña'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500
```

---

## Sección 13: Endpoint para Crear Usuarios (Solo Super Admin)

### 13.1 Implementar `POST /api/v1/usuarios`

**Archivo:** [app.py](app.py)
**Ubicación:** Después del endpoint de cambio de contraseña

**Implementación:**
```python
@app.route('/api/v1/usuarios', methods=['POST'])
@permiso_requerido('crear:usuario')  # O usar validación directa de super_admin
def crear_usuario():
    """
    Endpoint para crear nuevos usuarios.
    SOLO accesible por super_admin.
    
    Request:
    {
        "email": "usuario@ejemplo.com",
        "password": "contraseña_temporal",
        "id_rol": 2,
        "nombre": "Juan",
        "apellido": "Pérez",
        "residencias": [1, 2]  # Lista de id_residencia
    }
    """
    try:
        # Verificar que solo super_admin puede crear usuarios
        if g.id_rol != SUPER_ADMIN_ROLE_ID:
            return jsonify({'error': 'Solo super administradores pueden crear usuarios'}), 403
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        email = data.get('email')
        password = data.get('password')
        id_rol = data.get('id_rol')
        residencias = data.get('residencias', [])
        
        if not email or not password or not id_rol:
            return jsonify({'error': 'Email, contraseña e id_rol son requeridos'}), 400
        
        if not residencias or len(residencias) == 0:
            return jsonify({'error': 'Debe asignar al menos una residencia'}), 400
        
        # Validar formato de email
        if '@' not in email:
            return jsonify({'error': 'Email inválido'}), 400
        
        # Validar que la contraseña tenga mínimo de seguridad
        if len(password) < 8:
            return jsonify({'error': 'La contraseña debe tener al menos 8 caracteres'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el email no exista
            cursor.execute("SELECT id_usuario FROM usuario WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({'error': 'El email ya está registrado'}), 409
            
            # Verificar que el rol existe
            cursor.execute("SELECT id_rol FROM rol WHERE id_rol = %s", (id_rol,))
            if not cursor.fetchone():
                return jsonify({'error': 'Rol no encontrado'}), 404
            
            # Hashear contraseña
            password_hash = generate_password_hash(password)
            
            # Crear usuario
            cursor.execute("""
                INSERT INTO usuario (email, password_hash, id_rol, nombre, apellido, requiere_cambio_clave)
                VALUES (%s, %s, %s, %s, %s, TRUE)
                RETURNING id_usuario
            """, (
                email,
                password_hash,
                id_rol,
                data.get('nombre'),
                data.get('apellido')
            ))
            
            id_usuario = cursor.fetchone()[0]
            
            # Asignar residencias
            for id_residencia in residencias:
                cursor.execute("""
                    INSERT INTO usuario_residencia (id_usuario, id_residencia)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                """, (id_usuario, id_residencia))
            
            conn.commit()
            
            return jsonify({
                'id_usuario': id_usuario,
                'mensaje': 'Usuario creado exitosamente. Debe cambiar su contraseña en el primer login.',
                'email': email,
                'requiere_cambio_clave': True
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear usuario: {str(e)}")
            return jsonify({'error': 'Error al crear usuario'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500
```

---

## Sección 14: Middleware de Validación de Cambio de Contraseña

### 14.1 Agregar Validación en `before_request`

**Archivo:** [app.py](app.py)
**Ubicación:** Función `before_request()` (después de validar token)

**Agregar validación:**
```python
# Después de validar token y cargar residencias (línea ~120)
# Verificar si requiere cambio de contraseña (excepto para endpoints permitidos)

# Rutas que NO requieren cambio de contraseña
if request.path not in ['/api/v1/login', '/api/v1/usuario/cambio-clave', '/health', '/']:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT requiere_cambio_clave FROM usuario WHERE id_usuario = %s",
            (g.id_usuario,)
        )
        usuario = cursor.fetchone()
        if usuario and usuario[0]:  # Si requiere_cambio_clave = TRUE
            return jsonify({
                'error': 'Debes cambiar tu contraseña antes de continuar',
                'requiere_cambio_clave': True
            }), 403
    finally:
        cursor.close()
        conn.close()
```

---

## Resumen de Archivos a Modificar/Crear

1. **Nuevos archivos:**
   - `init_database.py` - Script de inicialización del super_admin
   - `migrate_usuario_schema.sql` - Script de migración del esquema

2. **Archivos a modificar:**
   - [app.py](app.py):
     - Actualizar función `login()` (agregar verificación requiere_cambio_clave)
     - Agregar endpoint `POST /api/v1/usuario/cambio-clave`
     - Agregar endpoint `POST /api/v1/usuarios` (solo super_admin)
     - Actualizar `before_request()` para validar cambio de contraseña
   - [create_schema.sql](create_schema.sql):
     - Agregar comentario sobre creación de super_admin

---

## Flujo Completo de Usuario Nuevo

1. **Super Admin crea usuario** → `POST /api/v1/usuarios` (solo super_admin)
   - Recibe email y contraseña temporal
   - Sistema hashea la contraseña
   - Usuario creado con `requiere_cambio_clave = TRUE`
   - Residencias asignadas en `usuario_residencia`

2. **Usuario hace login** → `POST /api/v1/login`
   - Verifica credenciales
   - Si `requiere_cambio_clave = TRUE` → retorna flag especial

3. **Usuario cambia contraseña** → `POST /api/v1/usuario/cambio-clave`
   - Valida contraseña actual
   - Hashea nueva contraseña
   - Actualiza `requiere_cambio_clave = FALSE`

4. **Usuario accede al sistema** → Todos los endpoints
   - Middleware valida que `requiere_cambio_clave = FALSE`
   - Si es TRUE, bloquea acceso (excepto cambio de contraseña)

---

## Notas de Seguridad

- ✅ Nunca insertar contraseñas en texto plano en BD
- ✅ Siempre usar `generate_password_hash()` de Werkzeug
- ✅ Primer super_admin se crea mediante script, no API
- ✅ Contraseñas temporales deben tener mínimo 8 caracteres
- ✅ Usuarios nuevos siempre requieren cambio de contraseña
- ✅ Solo super_admin puede crear nuevos usuarios

