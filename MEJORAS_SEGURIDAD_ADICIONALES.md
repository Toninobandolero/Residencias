# Mejoras de Seguridad Adicionales

## Mejoras Críticas Recomendadas

### 1. Validación Robusta de Contraseñas

**Problema Actual:** Solo valida longitud mínima (8 caracteres)

**Mejora:** Implementar política de contraseñas fuerte

```python
import re

def validate_password_strength(password):
    """
    Valida que la contraseña cumpla con requisitos de seguridad.
    
    Requisitos:
    - Mínimo 8 caracteres
    - Al menos una mayúscula
    - Al menos una minúscula
    - Al menos un número
    - Al menos un carácter especial
    """
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una mayúscula"
    
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener al menos una minúscula"
    
    if not re.search(r'\d', password):
        return False, "La contraseña debe contener al menos un número"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "La contraseña debe contener al menos un carácter especial"
    
    return True, None
```

**Aplicar en:**
- Endpoint de cambio de contraseña
- Endpoint de creación de usuarios

---

### 2. Rate Limiting para Prevenir Ataques de Fuerza Bruta

**Problema:** Login sin límite de intentos

**Mejora:** Implementar rate limiting con Flask-Limiter

**Agregar a requirements.txt:**
```
Flask-Limiter==3.5.0
```

**Implementación en app.py:**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configurar rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # En producción usar Redis
)

# Aplicar al endpoint de login
@app.route('/api/v1/login', methods=['POST'])
@limiter.limit("5 per minute")  # Máximo 5 intentos por minuto por IP
def login():
    # ... código existente
```

---

### 3. Logging de Seguridad y Auditoría

**Problema:** No hay registro de eventos críticos

**Mejora:** Implementar logging de seguridad

**Crear tabla de auditoría (opcional pero recomendado):**
```sql
CREATE TABLE IF NOT EXISTS log_auditoria (
    id_log SERIAL PRIMARY KEY,
    id_usuario INTEGER,
    tipo_evento VARCHAR(100) NOT NULL,  -- 'login_exitoso', 'login_fallido', 'cambio_clave', 'crear_usuario', etc.
    ip_address VARCHAR(45),
    user_agent TEXT,
    detalles JSONB,
    fecha_evento TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_usuario) REFERENCES usuario(id_usuario)
);
```

**Función helper para logging:**
```python
def log_security_event(tipo_evento, id_usuario=None, detalles=None):
    """
    Registra eventos de seguridad para auditoría.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        cursor.execute("""
            INSERT INTO log_auditoria (id_usuario, tipo_evento, ip_address, user_agent, detalles)
            VALUES (%s, %s, %s, %s, %s)
        """, (id_usuario, tipo_evento, ip_address, user_agent, json.dumps(detalles) if detalles else None))
        
        conn.commit()
    except Exception as e:
        app.logger.error(f"Error al registrar evento de seguridad: {str(e)}")
    finally:
        cursor.close()
        conn.close()
```

**Aplicar logging en:**
- Login exitoso
- Login fallido (con email intentado)
- Cambio de contraseña
- Creación de usuarios
- Accesos denegados (403)

---

### 4. Validación Mejorada de Email

**Problema:** Validación básica con `@` solamente

**Mejora:** Usar regex robusto o librería especializada

```python
import re

def validate_email(email):
    """
    Valida formato de email con regex robusto.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
```

**O usar validators existentes** (ya está importado `validate_email` en app.py)

---

### 5. Verificación de Residencias Existentes

**Problema:** Al asignar residencias a usuarios, no se verifica que existan

**Mejora:** Validar que todas las residencias existen antes de asignar

```python
# En endpoint de crear usuario, antes de insertar en usuario_residencia:
# Verificar que todas las residencias existen
cursor.execute("""
    SELECT id_residencia FROM residencia 
    WHERE id_residencia IN ({}) AND activa = TRUE
""".format(','.join(['%s'] * len(residencias))), tuple(residencias))

residencias_validas = [row[0] for row in cursor.fetchall()]

if len(residencias_validas) != len(residencias):
    return jsonify({
        'error': 'Una o más residencias no existen o están inactivas',
        'residencias_invalidas': [r for r in residencias if r not in residencias_validas]
    }), 400
```

---

### 6. Configuración de CORS para Producción

**Problema:** CORS configurado de forma permisiva (`CORS(app)`)

**Mejora:** Restringir orígenes en producción

```python
# En app.py, después de crear Flask app:
if os.getenv('FLASK_ENV') == 'production':
    CORS(app, origins=[
        'https://tu-dominio.com',
        'https://www.tu-dominio.com'
    ])
else:
    # Desarrollo: permitir localhost
    CORS(app, origins=[
        'http://localhost:5000',
        'http://127.0.0.1:5000'
    ])
```

---

### 7. Protección contra Inyección SQL

**Estado Actual:** ✅ Ya se usan parámetros preparados (`%s`), esto está bien

**Mejora Adicional:** Validar que `g.residencias_acceso` no esté vacío antes de construir queries IN

```python
# En build_residencia_filter:
if not g.residencias_acceso or len(g.residencias_acceso) == 0:
    # Usuario sin residencias asignadas
    return 'WHERE FALSE', []  # Retorna query que no devuelve resultados
```

---

### 8. Validación de Rol al Crear Usuarios

**Mejora:** Verificar que el super_admin no pueda crear otro super_admin por error

```python
# En endpoint de crear usuario:
# Prevenir crear super_admin accidentalmente (requiere proceso especial)
if id_rol == SUPER_ADMIN_ROLE_ID:
    return jsonify({
        'error': 'No se puede crear super_admin a través de este endpoint. Contacte al administrador del sistema.'
    }), 403
```

---

### 9. Token JWT con Refresh Tokens (Opcional pero Recomendado)

**Mejora Futura:** Implementar refresh tokens para mayor seguridad

- Access token: Corta duración (15-30 min)
- Refresh token: Larga duración (7 días)
- Refresh token almacenado en BD (puede revocarse)

**Prioridad:** Media - Puede implementarse después del MVP

---

### 10. Headers de Seguridad HTTP

**Mejora:** Agregar headers de seguridad HTTP

```python
@app.after_request
def after_request(response):
    """Agregar headers de seguridad HTTP"""
    if os.getenv('FLASK_ENV') == 'production':
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

---

## Priorización de Mejoras

### 🔴 CRÍTICAS (Implementar Ahora):
1. ✅ Validación robusta de contraseñas
2. ✅ Rate limiting en login
3. ✅ Logging de seguridad (login fallido, cambios críticos)
4. ✅ Verificación de residencias existentes

### 🟠 IMPORTANTES (Implementar Pronto):
5. ✅ Configuración CORS para producción
6. ✅ Validación mejorada de email
7. ✅ Headers de seguridad HTTP

### 🟡 OPCIONALES (Mejoras Futuras):
8. ⚠️ Tabla de auditoría completa
9. ⚠️ Refresh tokens
10. ⚠️ Prevención de creación accidental de super_admin

---

## Recomendación Final

**Implementar ahora (junto con el plan principal):**
- Validación robusta de contraseñas
- Rate limiting en login
- Logging básico de seguridad (sin tabla, solo app.logger)
- Verificación de residencias existentes
- Validación mejorada de email

**Implementar después (mejoras incrementales):**
- Configuración CORS para producción
- Headers de seguridad HTTP
- Tabla de auditoría completa

---

## Nota sobre Rate Limiting

Si no quieres agregar dependencias nuevas (Flask-Limiter), se puede implementar un rate limiting simple en memoria:

```python
from collections import defaultdict
from datetime import datetime, timedelta

# Diccionario simple para tracking (en producción usar Redis)
login_attempts = defaultdict(list)

def check_rate_limit(ip, max_attempts=5, window_minutes=1):
    """Verifica rate limit simple en memoria"""
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=window_minutes)
    
    # Limpiar intentos antiguos
    login_attempts[ip] = [t for t in login_attempts[ip] if t > window_start]
    
    # Verificar límite
    if len(login_attempts[ip]) >= max_attempts:
        return False
    
    # Registrar intento
    login_attempts[ip].append(now)
    return True
```

