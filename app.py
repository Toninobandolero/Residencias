"""
Aplicación principal Flask para el sistema de gestión de residencias Violetas.
Implementa autenticación JWT, permisos granulares y filtrado de datos por residencia.
"""
import os
import jwt
import re
import json
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from io import BytesIO
from flask import Flask, request, jsonify, g, send_from_directory, Response
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from db_connector import get_db_connection
from storage_manager import upload_document, get_document_url, delete_document
from validators import (
    validate_residente_data, validate_cobro_data, validate_monto,
    validate_residencia_id, validate_estado, validate_metodo_pago,
    validate_text, validate_email, validate_phone, validate_personal_data,
    validate_turno_extra_data
)
import mimetypes

# Cargar variables de entorno desde .env
load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)  # Habilitar CORS para el frontend

# Configuración
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
if not JWT_SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY debe estar definida como variable de entorno")

app.config['JSON_SORT_KEYS'] = False
app.config['JSON_AS_ASCII'] = False  # Permitir caracteres Unicode en JSON (ñ, acentos, etc.)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

# Constantes de seguridad
SUPER_ADMIN_ROLE_ID = 1  # ID fijo del rol super_admin

# Rate limiting simple en memoria (en producción usar Redis)
login_attempts = defaultdict(list)


def require_auth(f):
    """
    Decorador para proteger rutas que requieren autenticación.
    Útil para aplicar manualmente en rutas específicas si es necesario.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # La validación se hace en before_request, este decorador solo marca la ruta
        return f(*args, **kwargs)
    
    return decorated_function


def validate_password_strength(password):
    """
    Valida que la contraseña cumpla con requisitos de seguridad.
    
    Requisitos:
    - Mínimo 8 caracteres
    - Al menos una mayúscula
    - Al menos una minúscula
    - Al menos un número
    - Al menos un carácter especial
    
    Returns:
        tuple: (is_valid, error_message)
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


def check_rate_limit(ip, max_attempts=5, window_minutes=1):
    """
    Verifica rate limit simple en memoria para prevenir ataques de fuerza bruta.
    
    Args:
        ip: Dirección IP del cliente
        max_attempts: Número máximo de intentos permitidos
        window_minutes: Ventana de tiempo en minutos
        
    Returns:
        bool: True si puede continuar, False si excedió el límite
    """
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


def log_security_event(tipo_evento, id_usuario=None, detalles=None):
    """
    Registra eventos de seguridad para auditoría.
    
    Args:
        tipo_evento: Tipo de evento ('login_exitoso', 'login_fallido', 'cambio_clave', etc.)
        id_usuario: ID del usuario (opcional)
        detalles: Diccionario con detalles adicionales (opcional)
    """
    try:
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        log_data = {
            'tipo': tipo_evento,
            'id_usuario': id_usuario,
            'ip': ip_address,
            'user_agent': user_agent,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if detalles:
            log_data.update(detalles)
        
        app.logger.info(f"SECURITY: {json.dumps(log_data)}")
    except Exception as e:
        app.logger.error(f"Error al registrar evento de seguridad: {str(e)}")


def validate_residencia_access(id_residencia_from_db, allow_super_admin=True):
    """
    Valida que el id_residencia del recurso esté en la lista de acceso del usuario.
    
    Args:
        id_residencia_from_db: El id_residencia del registro obtenido de la BD
        allow_super_admin: Si True, permite acceso a super_admin (rol 1)
        
    Returns:
        tuple: (is_valid, error_response) donde error_response es None si es válido
    """
    # BYPASS para super_admin
    if allow_super_admin and g.id_rol == SUPER_ADMIN_ROLE_ID:
        return True, None
    
    # Verificar que la residencia está en la lista de acceso
    if not hasattr(g, 'residencias_acceso') or id_residencia_from_db not in g.residencias_acceso:
        return False, (jsonify({'error': 'No tienes permisos para acceder a este recurso'}), 403)
    
    return True, None


def build_residencia_filter(table_alias='', column_name='id_residencia'):
    """
    Construye la cláusula WHERE para filtrar por residencias de acceso.
    
    Args:
        table_alias: Alias de la tabla (ej: 'r.' o 'p.')
        column_name: Nombre de la columna (default: 'id_residencia')
        
    Returns:
        tuple: (sql_condition, params)
               - Si super_admin: (None, None) = sin filtro
               - Si usuario normal: ('WHERE ... IN (...)', [lista_ids])
    """
    if g.id_rol == SUPER_ADMIN_ROLE_ID:
        return None, None
    
    if not hasattr(g, 'residencias_acceso') or not g.residencias_acceso:
        # Usuario sin residencias (no debería pasar, pero por seguridad)
        return 'WHERE FALSE', []  # WHERE FALSE = no resultados
    
    column = f"{table_alias}{column_name}" if table_alias else column_name
    placeholders = ','.join(['%s'] * len(g.residencias_acceso))
    return f"WHERE {column} IN ({placeholders})", g.residencias_acceso


def permiso_requerido(nombre_permiso):
    """
    Decorador que valida permisos granulares para endpoints.
    
    Lógica:
    1. Valida JWT (ya hecho en before_request)
    2. Si es super_admin (id_rol = 1): BYPASS TOTAL (retorna True inmediatamente)
    3. Si NO es super_admin: Consulta DB para verificar permiso
    4. Adjunta lista de residencias a g.residencias_acceso (ya hecho en before_request)
    
    Args:
        nombre_permiso: String del permiso (ej: "escribir:tratamiento", "leer:residente")
        
    Returns:
        Decorador de función Flask
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Validación JWT ya hecha en before_request
            # g.id_usuario y g.id_rol ya están disponibles
            
            # 2. BYPASS para super_admin
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                return f(*args, **kwargs)
            
            # 3. Verificar permiso en BD
            conn = get_db_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM rol_permiso rp
                    JOIN permiso p ON rp.id_permiso = p.id_permiso
                    WHERE rp.id_rol = %s 
                      AND p.nombre = %s
                """, (g.id_rol, nombre_permiso))
                
                tiene_permiso = cursor.fetchone()[0] > 0
                
                if not tiene_permiso:
                    log_security_event('acceso_denegado', g.id_usuario, {
                        'permiso_requerido': nombre_permiso,
                        'endpoint': request.path
                    })
                    return jsonify({
                        'error': 'No tienes permisos para realizar esta acción',
                        'permiso_requerido': nombre_permiso
                    }), 403
                    
            finally:
                cursor.close()
                conn.close()
            
            # 4. Continuar con la ejecución del endpoint
            return f(*args, **kwargs)
            
        return decorated_function
    return decorator


@app.before_request
def before_request():
    """
    Middleware que aplica autenticación a todas las rutas excepto las públicas.
    Valida el token JWT, carga residencias del usuario y valida cambio de contraseña.
    """
    # Rutas públicas que no requieren autenticación
    public_paths = ['/api/v1/login', '/health', '/']
    # Rutas que requieren autenticación pero permiten cambio de contraseña
    # Incluye rutas para permitir que el usuario actualice su propia información (incluyendo contraseña)
    rutas_cambio_clave = ['/api/v1/usuario/cambio-clave', '/api/v1/usuarios/me']
    # Rutas que permiten actualización del propio usuario (incluyendo cambio de contraseña inicial)
    rutas_actualizacion_propia = ['/api/v1/usuarios']
    
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
        
        # Validar que los campos requeridos estén presentes (YA NO incluye id_residencia)
        if not all([g.id_usuario, g.id_rol]):
            return jsonify({'error': 'Token inválido: faltan campos requeridos'}), 401
            
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Token inválido'}), 401
    
    # Cargar residencias del usuario desde usuario_residencia
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Si es super_admin, establecer lista vacía (bypass total)
        if g.id_rol == SUPER_ADMIN_ROLE_ID:
            g.residencias_acceso = []  # Lista vacía = acceso total a todas las residencias
        else:
            # Cargar residencias desde usuario_residencia
            cursor.execute("""
                SELECT ur.id_residencia 
                FROM usuario_residencia ur
                JOIN residencia r ON ur.id_residencia = r.id_residencia
                WHERE ur.id_usuario = %s AND r.activa = TRUE
            """, (g.id_usuario,))
            
            g.residencias_acceso = [row[0] for row in cursor.fetchall()]
            
            # Validar que el usuario tenga al menos una residencia asignada
            if not g.residencias_acceso:
                return jsonify({
                    'error': 'Usuario sin residencias asignadas. Contacte al administrador.'
                }), 403
        
        # Validar cambio de contraseña obligatorio (excepto para rutas permitidas)
        # Permitir también actualización del propio usuario (para cambiar contraseña inicial)
        # Solo permitir si es PUT a su propia cuenta (para cambiar contraseña en primer login)
        es_actualizacion_propia = (request.path.startswith('/api/v1/usuarios/') and 
                                   request.method == 'PUT' and 
                                   request.path.split('/')[-1].isdigit() and
                                   int(request.path.split('/')[-1]) == g.id_usuario)
        if request.path not in rutas_cambio_clave and not es_actualizacion_propia:
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
    
    return None


@app.route('/')
def index():
    """Sirve la página principal del frontend."""
    return send_from_directory('static', 'index.html')


@app.route('/favicon.ico')
def favicon():
    """Maneja la petición del favicon."""
    return '', 204  # No Content


@app.route('/health', methods=['GET'])
def health_check():
    """
    Endpoint de health check para verificar el estado del servicio.
    """
    return jsonify({
        'status': 'ok',
        'service': 'Violetas Backend API',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


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
        
        # Rate limiting: verificar intentos de login
        ip_address = request.remote_addr
        if not check_rate_limit(ip_address, max_attempts=5, window_minutes=1):
            log_security_event('login_rate_limit_excedido', None, {'email': email, 'ip': ip_address})
            return jsonify({
                'error': 'Demasiados intentos de login. Intenta nuevamente en 1 minuto.'
            }), 429
        
        # Conectar a la base de datos
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Buscar usuario por email (SIN id_residencia, ahora se obtiene de usuario_residencia)
            cursor.execute(
                "SELECT id_usuario, email, password_hash, id_rol, requiere_cambio_clave FROM usuario WHERE email = %s",
                (email,)
            )
            usuario = cursor.fetchone()
            
            if not usuario:
                log_security_event('login_fallido', None, {'email': email, 'razon': 'usuario_no_encontrado'})
                return jsonify({'error': 'Credenciales inválidas'}), 401
            
            id_usuario, email_db, password_hash, id_rol, requiere_cambio_clave = usuario
            
            # Verificar contraseña
            if not check_password_hash(password_hash, password):
                log_security_event('login_fallido', id_usuario, {'email': email, 'razon': 'contraseña_incorrecta'})
                return jsonify({'error': 'Credenciales inválidas'}), 401
            
            # Login exitoso - generar token JWT (SIN id_residencia)
            payload = {
                'id_usuario': id_usuario,
                'id_rol': id_rol,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }
            
            token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
            
            log_security_event('login_exitoso', id_usuario, {'email': email, 'requiere_cambio_clave': requiere_cambio_clave})
            
            response = {
                'token': token
            }
            
            # Si requiere cambio de contraseña, agregar flag
            if requiere_cambio_clave:
                response['requiere_cambio_clave'] = True
                response['mensaje'] = 'Debes cambiar tu contraseña antes de continuar'
            
            return jsonify(response), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except ValueError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        app.logger.error(f"Error en login: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


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
        
        # Validar fuerza de la nueva contraseña
        is_valid, error_msg = validate_password_strength(password_nuevo)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
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
                log_security_event('cambio_clave_fallido', id_usuario, {'razon': 'contraseña_actual_incorrecta'})
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
            
            log_security_event('cambio_clave_exitoso', id_usuario)
            
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


@app.route('/api/v1/usuarios', methods=['POST'])
@permiso_requerido('crear:usuario')  # Nota: super_admin tiene bypass automático
def crear_usuario():
    """
    Endpoint para crear nuevos usuarios.
    SOLO accesible por super_admin (tiene bypass en el decorador).
    
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
        # Verificación adicional: solo super_admin puede crear usuarios
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
        
        # Prevenir creación accidental de super_admin
        if id_rol == SUPER_ADMIN_ROLE_ID:
            return jsonify({
                'error': 'No se puede crear super_admin a través de este endpoint. Contacte al administrador del sistema.'
            }), 403
        
        # Validar formato de email
        is_valid_email, error_msg = validate_email(email)
        if not is_valid_email:
            return jsonify({'error': error_msg or 'Email inválido'}), 400
        
        # Validar fuerza de contraseña
        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el email no exista
            cursor.execute("SELECT id_usuario FROM usuario WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({'error': 'El email ya está registrado'}), 409
            
            # Verificar que el rol existe
            cursor.execute("SELECT id_rol FROM rol WHERE id_rol = %s AND activo = TRUE", (id_rol,))
            if not cursor.fetchone():
                return jsonify({'error': 'Rol no encontrado o inactivo'}), 404
            
            # Verificar que todas las residencias existen y están activas
            placeholders = ','.join(['%s'] * len(residencias))
            cursor.execute(f"""
                SELECT id_residencia FROM residencia 
                WHERE id_residencia IN ({placeholders}) AND activa = TRUE
            """, tuple(residencias))
            
            residencias_validas = [row[0] for row in cursor.fetchall()]
            
            if len(residencias_validas) != len(residencias):
                residencias_invalidas = [r for r in residencias if r not in residencias_validas]
                return jsonify({
                    'error': 'Una o más residencias no existen o están inactivas',
                    'residencias_invalidas': residencias_invalidas
                }), 400
            
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
            for id_residencia in residencias_validas:
                cursor.execute("""
                    INSERT INTO usuario_residencia (id_usuario, id_residencia)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                """, (id_usuario, id_residencia))
            
            conn.commit()
            
            log_security_event('usuario_creado', g.id_usuario, {
                'usuario_creado_id': id_usuario,
                'email': email,
                'id_rol': id_rol,
                'residencias': residencias_validas
            })
            
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


# ============================================================================
# ENDPOINTS DE RESIDENTES
# ============================================================================

@app.route('/api/v1/residencias/<int:id_residencia>/habitaciones-ocupadas', methods=['GET'])
def obtener_habitaciones_ocupadas(id_residencia):
    """Obtiene las habitaciones ocupadas de una residencia (solo residentes activos)."""
    try:
        # Verificar que el usuario tenga acceso a esta residencia
        is_valid, error_response = validate_residencia_access(id_residencia)
        if not is_valid:
            return error_response
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Consulta simplificada sin expresiones regulares complejas
            cursor.execute("""
                SELECT DISTINCT habitacion
                FROM residente
                WHERE id_residencia = %s
                  AND activo = TRUE
                  AND habitacion IS NOT NULL
                  AND habitacion != ''
                ORDER BY habitacion
            """, (id_residencia,))
            
            habitaciones_ocupadas = [str(row[0]) for row in cursor.fetchall()]
            
            # Ordenar numéricamente en Python si es posible
            def sort_key(h):
                try:
                    return (0, int(h))  # Numeros primero
                except ValueError:
                    return (1, h)  # Texto después
            
            habitaciones_ocupadas.sort(key=sort_key)
            
            return jsonify({
                'habitaciones_ocupadas': habitaciones_ocupadas,
                'total': len(habitaciones_ocupadas)
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        import traceback
        error_msg = str(e)
        error_trace = traceback.format_exc()
        app.logger.error(f"Error al obtener habitaciones ocupadas: {error_msg}\n{error_trace}")
        return jsonify({
            'error': 'Error al obtener habitaciones ocupadas',
            'details': error_msg
        }), 500


@app.route('/api/v1/residentes', methods=['GET'])
def listar_residentes():
    """
    Lista todos los residentes ordenados por residencia y habitación.
    Muestra todas las residencias ordenadas.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar qué columnas opcionales existen
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'residente' 
                  AND column_name IN ('grupo_sanguineo', 'alergias', 'diagnosticos', 'restricciones_dieteticas',
                                      'nivel_dependencia', 'movilidad', 'medico_referencia', 'telefono_medico',
                                      'motivo_baja', 'fecha_baja')
            """)
            columnas_existentes = {row[0] for row in cursor.fetchall()}
            
            # Construir la consulta dinámicamente
            campos_opcionales = []
            if 'grupo_sanguineo' in columnas_existentes:
                campos_opcionales.append('r.grupo_sanguineo')
            else:
                campos_opcionales.append('NULL as grupo_sanguineo')
            
            if 'alergias' in columnas_existentes:
                campos_opcionales.append('r.alergias')
            else:
                campos_opcionales.append('NULL as alergias')
            
            if 'diagnosticos' in columnas_existentes:
                campos_opcionales.append('r.diagnosticos')
            else:
                campos_opcionales.append('NULL as diagnosticos')
            
            if 'restricciones_dieteticas' in columnas_existentes:
                campos_opcionales.append('r.restricciones_dieteticas')
            else:
                campos_opcionales.append('NULL as restricciones_dieteticas')
            
            if 'nivel_dependencia' in columnas_existentes:
                campos_opcionales.append('r.nivel_dependencia')
            else:
                campos_opcionales.append('NULL as nivel_dependencia')
            
            if 'movilidad' in columnas_existentes:
                campos_opcionales.append('r.movilidad')
            else:
                campos_opcionales.append('NULL as movilidad')
            
            if 'medico_referencia' in columnas_existentes:
                campos_opcionales.append('r.medico_referencia')
            else:
                campos_opcionales.append('NULL as medico_referencia')
            
            if 'telefono_medico' in columnas_existentes:
                campos_opcionales.append('r.telefono_medico')
            else:
                campos_opcionales.append('NULL as telefono_medico')
            
            if 'motivo_baja' in columnas_existentes:
                campos_opcionales.append('r.motivo_baja')
            else:
                campos_opcionales.append('NULL as motivo_baja')
            
            if 'fecha_baja' in columnas_existentes:
                campos_opcionales.append('r.fecha_baja')
            else:
                campos_opcionales.append('NULL as fecha_baja')
            
            campos_opcionales_str = ', ' + ', '.join(campos_opcionales)
            
            # Construir query base
            query = f"""
                SELECT r.id_residente, r.id_residencia, r.nombre, r.apellido, r.documento_identidad, 
                       r.fecha_nacimiento, r.telefono, r.direccion, r.contacto_emergencia,
                       r.telefono_emergencia, r.activo, r.fecha_ingreso, r.habitacion,
                       r.costo_habitacion, r.servicios_extra, r.medicaciones, r.peculiaridades, 
                       r.metodo_pago_preferido, r.fecha_creacion
                       {campos_opcionales_str},
                       res.nombre as nombre_residencia
                FROM residente r
                JOIN residencia res ON r.id_residencia = res.id_residencia
            """
            
            # Filtrar por residencias según acceso del usuario
            params = []
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                # Super admin: sin filtro
                pass
            else:
                # Usuario normal: filtrar por lista de residencias
                if not g.residencias_acceso:
                    return jsonify({'residentes': [], 'total': 0}), 200
                
                placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                query += f" WHERE r.id_residencia IN ({placeholders})"
                params = g.residencias_acceso
            
            query += """
                ORDER BY r.id_residencia, 
                         CASE 
                             WHEN r.habitacion ~ '^[0-9]+$' THEN r.habitacion::INTEGER
                             ELSE 999999
                         END,
                         r.habitacion
            """
            
            cursor.execute(query, tuple(params) if params else None)
            
            residentes = cursor.fetchall()
            
            # Índices base (campos que siempre existen)
            idx_base = 18  # Después de fecha_creacion
            
            resultado = []
            for res in residentes:
                idx = idx_base
                resultado.append({
                    'id_residente': res[0],
                    'id_residencia': res[1],
                    'nombre': res[2],
                    'apellido': res[3],
                    'documento_identidad': res[4],
                    'fecha_nacimiento': str(res[5]) if res[5] else None,
                    'telefono': res[6],
                    'direccion': res[7],
                    'contacto_emergencia': res[8],
                    'telefono_emergencia': res[9],
                    'activo': res[10],
                    'fecha_ingreso': str(res[11]) if res[11] else None,
                    'habitacion': res[12],
                    'costo_habitacion': float(res[13]) if res[13] else None,
                    'servicios_extra': res[14],
                    'medicaciones': res[15],
                    'peculiaridades': res[16],
                    'metodo_pago_preferido': res[17],
                    'fecha_creacion': res[18].isoformat() if res[18] else None,
                    'grupo_sanguineo': res[idx] if len(res) > idx else None,
                    'alergias': res[idx + 1] if len(res) > idx + 1 else None,
                    'diagnosticos': res[idx + 2] if len(res) > idx + 2 else None,
                    'restricciones_dieteticas': res[idx + 3] if len(res) > idx + 3 else None,
                    'nivel_dependencia': res[idx + 4] if len(res) > idx + 4 else None,
                    'movilidad': res[idx + 5] if len(res) > idx + 5 else None,
                    'medico_referencia': res[idx + 6] if len(res) > idx + 6 else None,
                    'telefono_medico': res[idx + 7] if len(res) > idx + 7 else None,
                    'motivo_baja': res[idx + 8] if len(res) > idx + 8 else None,
                    'fecha_baja': str(res[idx + 9]) if len(res) > idx + 9 and res[idx + 9] else None,
                    'nombre_residencia': res[idx + 10] if len(res) > idx + 10 else None
                })
            
            return jsonify({'residentes': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar residentes: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': f'Error al obtener residentes: {str(e)}'}), 500


@app.route('/api/v1/residentes/<int:id_residente>', methods=['GET'])
def obtener_residente(id_residente):
    """Obtiene un residente específico. Permite obtener residentes de cualquier residencia para poder editarlos."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar qué columnas opcionales existen
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'residente' 
                  AND column_name IN ('grupo_sanguineo', 'alergias', 'diagnosticos', 'restricciones_dieteticas',
                                      'nivel_dependencia', 'movilidad', 'medico_referencia', 'telefono_medico',
                                      'motivo_baja', 'fecha_baja')
            """)
            columnas_existentes = {row[0] for row in cursor.fetchall()}
            
            # Construir la consulta dinámicamente
            campos_opcionales = []
            if 'grupo_sanguineo' in columnas_existentes:
                campos_opcionales.append('r.grupo_sanguineo')
            else:
                campos_opcionales.append('NULL as grupo_sanguineo')
            
            if 'alergias' in columnas_existentes:
                campos_opcionales.append('r.alergias')
            else:
                campos_opcionales.append('NULL as alergias')
            
            if 'diagnosticos' in columnas_existentes:
                campos_opcionales.append('r.diagnosticos')
            else:
                campos_opcionales.append('NULL as diagnosticos')
            
            if 'restricciones_dieteticas' in columnas_existentes:
                campos_opcionales.append('r.restricciones_dieteticas')
            else:
                campos_opcionales.append('NULL as restricciones_dieteticas')
            
            if 'nivel_dependencia' in columnas_existentes:
                campos_opcionales.append('r.nivel_dependencia')
            else:
                campos_opcionales.append('NULL as nivel_dependencia')
            
            if 'movilidad' in columnas_existentes:
                campos_opcionales.append('r.movilidad')
            else:
                campos_opcionales.append('NULL as movilidad')
            
            if 'medico_referencia' in columnas_existentes:
                campos_opcionales.append('r.medico_referencia')
            else:
                campos_opcionales.append('NULL as medico_referencia')
            
            if 'telefono_medico' in columnas_existentes:
                campos_opcionales.append('r.telefono_medico')
            else:
                campos_opcionales.append('NULL as telefono_medico')
            
            if 'motivo_baja' in columnas_existentes:
                campos_opcionales.append('r.motivo_baja')
            else:
                campos_opcionales.append('NULL as motivo_baja')
            
            if 'fecha_baja' in columnas_existentes:
                campos_opcionales.append('r.fecha_baja')
            else:
                campos_opcionales.append('NULL as fecha_baja')
            
            campos_opcionales_str = ', ' + ', '.join(campos_opcionales)
            
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
            
            # Validar acceso a la residencia
            is_valid, error_response = validate_residencia_access(res[1])  # res[1] es id_residencia
            if not is_valid:
                return error_response
            
            # Índices base (campos que siempre existen)
            idx = 19  # Después de fecha_creacion
            
            resultado = {
                'id_residente': res[0],
                'id_residencia': res[1],
                'nombre': res[2],
                'apellido': res[3],
                'documento_identidad': res[4],
                'fecha_nacimiento': str(res[5]) if res[5] else None,
                'telefono': res[6],
                'direccion': res[7],
                'contacto_emergencia': res[8],
                'telefono_emergencia': res[9],
                'activo': res[10],
                'fecha_ingreso': str(res[11]) if res[11] else None,
                'habitacion': res[12],
                'costo_habitacion': float(res[13]) if res[13] else None,
                'servicios_extra': res[14],
                'medicaciones': res[15],
                'peculiaridades': res[16],
                'metodo_pago_preferido': res[17],
                'fecha_creacion': res[18].isoformat() if res[18] else None,
                'grupo_sanguineo': res[idx] if len(res) > idx else None,
                'alergias': res[idx + 1] if len(res) > idx + 1 else None,
                'diagnosticos': res[idx + 2] if len(res) > idx + 2 else None,
                'restricciones_dieteticas': res[idx + 3] if len(res) > idx + 3 else None,
                'nivel_dependencia': res[idx + 4] if len(res) > idx + 4 else None,
                'movilidad': res[idx + 5] if len(res) > idx + 5 else None,
                'medico_referencia': res[idx + 6] if len(res) > idx + 6 else None,
                'telefono_medico': res[idx + 7] if len(res) > idx + 7 else None,
                'motivo_baja': res[idx + 8] if len(res) > idx + 8 else None,
                'fecha_baja': str(res[idx + 9]) if len(res) > idx + 9 and res[idx + 9] else None
            }
            
            return jsonify(resultado), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al obtener residente: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': f'Error al obtener residente: {str(e)}'}), 500


@app.route('/api/v1/residentes', methods=['POST'])
def crear_residente():
    """
    Crea un nuevo residente. Permite elegir la residencia (Violetas 1 o Violetas 2).
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        # Validar datos con el módulo de validación
        is_valid, errors = validate_residente_data(data, is_update=False)
        if not is_valid:
            return jsonify({'error': 'Errores de validación', 'detalles': errors}), 400
        
        nombre = data.get('nombre')
        apellido = data.get('apellido')
        id_residencia = data.get('id_residencia')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que la residencia existe
            cursor.execute("SELECT id_residencia FROM residencia WHERE id_residencia = %s", (id_residencia,))
            if not cursor.fetchone():
                return jsonify({'error': 'Residencia no encontrada'}), 404
            
            cursor.execute("""
                INSERT INTO residente (id_residencia, nombre, apellido, documento_identidad,
                                     fecha_nacimiento, telefono, direccion, contacto_emergencia,
                                     telefono_emergencia, activo, fecha_ingreso, habitacion,
                                     costo_habitacion, servicios_extra, medicaciones, peculiaridades,
                                     metodo_pago_preferido, grupo_sanguineo, alergias, diagnosticos,
                                     restricciones_dieteticas, nivel_dependencia, movilidad,
                                     medico_referencia, telefono_medico)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_residente, fecha_creacion
            """, (
                id_residencia,
                nombre,
                apellido,
                data.get('documento_identidad'),
                data.get('fecha_nacimiento'),
                data.get('telefono'),
                data.get('direccion'),
                data.get('contacto_emergencia'),
                data.get('telefono_emergencia'),
                data.get('activo', True),
                data.get('fecha_ingreso'),
                data.get('habitacion'),
                data.get('costo_habitacion'),
                data.get('servicios_extra'),
                data.get('medicaciones'),
                data.get('peculiaridades'),
                data.get('metodo_pago_preferido'),
                data.get('grupo_sanguineo'),
                data.get('alergias'),
                data.get('diagnosticos'),
                data.get('restricciones_dieteticas'),
                data.get('nivel_dependencia'),
                data.get('movilidad'),
                data.get('medico_referencia'),
                data.get('telefono_medico')
            ))
            
            resultado = cursor.fetchone()
            id_residente = resultado[0]
            
            # Generar automáticamente cobro del mes siguiente si tiene costo_habitacion
            costo_habitacion = data.get('costo_habitacion')
            if costo_habitacion and costo_habitacion > 0:
                try:
                    # Calcular mes siguiente
                    hoy = datetime.now()
                    if hoy.month == 12:
                        siguiente_mes = datetime(hoy.year + 1, 1, 1)
                    else:
                        siguiente_mes = datetime(hoy.year, hoy.month + 1, 1)
                    
                    mes_siguiente_str = siguiente_mes.strftime('%Y-%m')
                    fecha_prevista = siguiente_mes.date()  # Día 1 del mes siguiente
                    
                    meses_espanol = {
                        1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril',
                        5: 'mayo', 6: 'junio', 7: 'julio', 8: 'agosto',
                        9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'
                    }
                    nombre_mes = meses_espanol.get(siguiente_mes.month, 'mes')
                    # Formato: "Diciembre 25", "Enero 26" (solo mes y año corto, sin "Pago")
                    año_corto = str(siguiente_mes.year)[-2:]  # Últimos 2 dígitos
                    concepto = f"{nombre_mes.capitalize()} {año_corto}"
                    metodo_pago = data.get('metodo_pago_preferido') or 'transferencia'
                    
                    # Verificar si ya existe un cobro para el mes siguiente con concepto "Pago [mes]"
                    # Prevenir duplicados: no puede haber dos cobros con concepto "Pago [mes]" para el mismo residente y mes
                    cursor.execute("""
                        SELECT id_pago FROM pago_residente
                        WHERE id_residente = %s 
                          AND id_residencia = %s
                          AND mes_pagado = %s
                          AND (concepto ILIKE 'enero %%' OR concepto ILIKE 'febrero %%' OR concepto ILIKE 'marzo %%' 
                               OR concepto ILIKE 'abril %%' OR concepto ILIKE 'mayo %%' OR concepto ILIKE 'junio %%'
                               OR concepto ILIKE 'julio %%' OR concepto ILIKE 'agosto %%' OR concepto ILIKE 'septiembre %%'
                               OR concepto ILIKE 'octubre %%' OR concepto ILIKE 'noviembre %%' OR concepto ILIKE 'diciembre %%'
                               OR concepto ILIKE 'Pago %%')
                    """, (id_residente, id_residencia, mes_siguiente_str))
                    
                    if not cursor.fetchone():
                        # Crear el cobro previsto para el mes siguiente
                        cursor.execute("""
                            INSERT INTO pago_residente (
                                id_residente, id_residencia, monto, fecha_pago, fecha_prevista,
                                mes_pagado, concepto, metodo_pago, estado, es_cobro_previsto
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            id_residente,
                            id_residencia,
                            costo_habitacion,
                            None,  # fecha_pago es NULL para cobros previstos
                            fecha_prevista,
                            mes_siguiente_str,
                            concepto,
                            metodo_pago,
                            'pendiente',
                            True
                        ))
                        app.logger.info(f"Cobro previsto generado automáticamente para nuevo residente {nombre} {apellido} (ID: {id_residente}): €{costo_habitacion}, mes: {mes_siguiente_str}")
                except Exception as e:
                    app.logger.error(f"Error al generar cobro previsto automático para nuevo residente {id_residente}: {str(e)}")
                    # No fallar la creación del residente si falla la generación del cobro
            
            conn.commit()
            
            return jsonify({
                'id_residente': id_residente,
                'mensaje': 'Residente creado exitosamente'
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear residente: {str(e)}")
            return jsonify({'error': 'Error al crear residente'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/residentes/<int:id_residente>/baja', methods=['POST'])
def dar_baja_residente(id_residente):
    """Da de baja a un residente con motivo y fecha."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        motivo_baja = data.get('motivo_baja')
        if not motivo_baja:
            return jsonify({'error': 'El motivo de baja es requerido'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el residente existe, está activo y pertenece a la residencia del usuario
            cursor.execute("""
                SELECT id_residente, activo, id_residencia FROM residente
                WHERE id_residente = %s
            """, (id_residente,))
            
            residente = cursor.fetchone()
            if not residente:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            # Verificar que el usuario tiene acceso a la residencia del residente
            is_valid, error_response = validate_residencia_access(residente[2])
            if not is_valid:
                return error_response
            
            if not residente[1]:  # Si ya está inactivo
                return jsonify({'error': 'El residente ya está dado de baja'}), 400
            
            # Verificar si las columnas de baja existen
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'residente' 
                  AND column_name IN ('motivo_baja', 'fecha_baja')
            """)
            columnas_baja = {row[0] for row in cursor.fetchall()}
            
            # Actualizar el residente: activo = False, motivo_baja, fecha_baja = hoy
            from datetime import date
            fecha_baja = date.today()
            
            # Construir la consulta dinámicamente según las columnas que existan
            # Al dar de baja, NO se libera la habitación (se mantiene para referencia histórica)
            # El sistema de habitaciones ocupadas filtra por activo = TRUE, así que no hay conflicto
            updates = ['activo = FALSE']
            valores = []
            
            if 'motivo_baja' in columnas_baja:
                updates.append('motivo_baja = %s')
                valores.append(motivo_baja)
            
            if 'fecha_baja' in columnas_baja:
                updates.append('fecha_baja = %s')
                valores.append(fecha_baja)
            
            valores.append(id_residente)
            
            query = f"""
                UPDATE residente
                SET {', '.join(updates)}
                WHERE id_residente = %s
                RETURNING id_residente
            """
            
            cursor.execute(query, tuple(valores))
            conn.commit()
            
            return jsonify({
                'mensaje': 'Residente dado de baja exitosamente',
                'id_residente': id_residente,
                'motivo_baja': motivo_baja if 'motivo_baja' in columnas_baja else None,
                'fecha_baja': str(fecha_baja) if 'fecha_baja' in columnas_baja else None
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al dar de baja al residente: {str(e)}")
            return jsonify({'error': 'Error al dar de baja al residente'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/residentes/<int:id_residente>/alta', methods=['POST'])
def dar_alta_residente(id_residente):
    """Reactiva un residente que estaba de baja (baja por error)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el residente existe y está inactivo
            cursor.execute("""
                SELECT id_residente, activo, id_residencia FROM residente
                WHERE id_residente = %s
            """, (id_residente,))
            
            residente = cursor.fetchone()
            if not residente:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            # Verificar que el usuario tiene acceso a la residencia del residente
            is_valid, error_response = validate_residencia_access(residente[2])
            if not is_valid:
                return error_response
            
            if residente[1]:  # Si ya está activo
                return jsonify({'error': 'El residente ya está activo'}), 400
            
            # Verificar si las columnas de baja existen
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'residente' 
                  AND column_name IN ('motivo_baja', 'fecha_baja')
            """)
            columnas_baja = {row[0] for row in cursor.fetchall()}
            
            # Reactivar el residente: activo = True, limpiar motivo_baja y fecha_baja
            updates = ['activo = TRUE']
            valores = []
            
            if 'motivo_baja' in columnas_baja:
                updates.append('motivo_baja = NULL')
            
            if 'fecha_baja' in columnas_baja:
                updates.append('fecha_baja = NULL')
            
            valores.append(id_residente)
            
            query = f"""
                UPDATE residente
                SET {', '.join(updates)}
                WHERE id_residente = %s
                RETURNING id_residente
            """
            
            cursor.execute(query, tuple(valores))
            conn.commit()
            
            return jsonify({
                'mensaje': 'Residente reactivado exitosamente',
                'id_residente': id_residente
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al reactivar al residente: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())
            return jsonify({'error': 'Error al reactivar al residente', 'details': str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/residentes/<int:id_residente>', methods=['DELETE'])
def eliminar_residente(id_residente):
    """Elimina completamente un residente de la base de datos."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el residente existe
            cursor.execute("""
                SELECT id_residente, id_residencia FROM residente
                WHERE id_residente = %s
            """, (id_residente,))
            
            residente = cursor.fetchone()
            if not residente:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            # Verificar que el usuario tiene acceso a la residencia del residente
            is_valid, error_response = validate_residencia_access(residente[1])
            if not is_valid:
                return error_response
            
            # Verificar que está dado de baja antes de eliminar
            cursor.execute("""
                SELECT activo FROM residente
                WHERE id_residente = %s
            """, (id_residente,))
            
            activo = cursor.fetchone()[0]
            if activo:
                return jsonify({'error': 'No se puede eliminar un residente activo. Primero debe darse de baja.'}), 400
            
            # Eliminar documentos asociados (si existe la tabla)
            try:
                cursor.execute("""
                    DELETE FROM documento_residente
                    WHERE id_residente = %s
                """, (id_residente,))
            except Exception as e:
                app.logger.warning(f"Error al eliminar documentos del residente {id_residente}: {str(e)}")
            
            # Eliminar pagos asociados antes de eliminar el residente
            # Esto es necesario porque hay una foreign key constraint
            try:
                cursor.execute("""
                    DELETE FROM pago_residente
                    WHERE id_residente = %s
                """, (id_residente,))
                app.logger.info(f"Pagos eliminados para residente {id_residente}: {cursor.rowcount}")
            except Exception as e:
                app.logger.warning(f"Error al eliminar pagos del residente {id_residente}: {str(e)}")
                # Si falla, intentar continuar de todas formas
            
            # Eliminar el residente
            cursor.execute("""
                DELETE FROM residente
                WHERE id_residente = %s
                RETURNING id_residente
            """, (id_residente,))
            
            conn.commit()
            
            return jsonify({
                'mensaje': 'Residente eliminado completamente',
                'id_residente': id_residente
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al eliminar al residente: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())
            return jsonify({'error': 'Error al eliminar al residente', 'details': str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/residentes/<int:id_residente>', methods=['PUT'])
def actualizar_residente(id_residente):
    """Actualiza un residente (solo de la residencia del usuario)."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        # Validar datos con el módulo de validación
        is_valid, errors = validate_residente_data(data, is_update=True)
        if not is_valid:
            return jsonify({'error': 'Errores de validación', 'detalles': errors}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Si se está cambiando la residencia, validar que sea 1 o 2
            nueva_residencia = data.get('id_residencia')
            if nueva_residencia is not None:
                valid, error = validate_residencia_id(nueva_residencia)
                if not valid:
                    return jsonify({'error': error}), 400
                # Verificar que la residencia existe
                cursor.execute("SELECT id_residencia FROM residencia WHERE id_residencia = %s", (nueva_residencia,))
                if not cursor.fetchone():
                    return jsonify({'error': 'Residencia no encontrada'}), 404
            
            # Verificar que el residente existe (sin filtrar por residencia para permitir cambio)
            cursor.execute("""
                SELECT id_residente, id_residencia FROM residente
                WHERE id_residente = %s
            """, (id_residente,))
            
            residente_actual = cursor.fetchone()
            if not residente_actual:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            # Validar acceso a la residencia actual del residente
            is_valid, error_response = validate_residencia_access(residente_actual[1])  # residente_actual[1] es id_residencia
            if not is_valid:
                return error_response
            
            # La residencia actual del residente (para el WHERE)
            id_residencia_actual = residente_actual[1]
            
            # Verificar qué columnas opcionales existen en la base de datos
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'residente' 
                  AND column_name IN ('grupo_sanguineo', 'alergias', 'diagnosticos', 'restricciones_dieteticas',
                                      'nivel_dependencia', 'movilidad', 'medico_referencia', 'telefono_medico',
                                      'motivo_baja', 'fecha_baja')
            """)
            columnas_existentes = {row[0] for row in cursor.fetchall()}
            
            # Campos base que siempre existen
            campos_base = [
                'id_residencia', 'nombre', 'apellido', 'documento_identidad', 'fecha_nacimiento',
                'telefono', 'direccion', 'contacto_emergencia', 'telefono_emergencia',
                'fecha_ingreso', 'habitacion', 'costo_habitacion',
                'servicios_extra', 'medicaciones', 'peculiaridades', 'metodo_pago_preferido'
            ]
            
            # Campos opcionales que pueden o no existir
            campos_opcionales = [
                'grupo_sanguineo', 'alergias', 'diagnosticos', 'restricciones_dieteticas',
                'nivel_dependencia', 'movilidad', 'medico_referencia', 'telefono_medico'
            ]
            
            # Construir lista completa de campos actualizables (solo los que existen)
            campos_actualizables = campos_base.copy()
            for campo in campos_opcionales:
                if campo in columnas_existentes:
                    campos_actualizables.append(campo)
            
            updates = []
            valores = []
            
            for campo in campos_actualizables:
                if campo in data:
                    updates.append(f"{campo} = %s")
                    valores.append(data[campo])
            
            if not updates:
                return jsonify({'error': 'No hay campos para actualizar'}), 400
            
            # Usar la residencia ACTUAL para el WHERE (antes del cambio)
            valores.extend([id_residente, id_residencia_actual])
            
            query = f"""
                UPDATE residente
                SET {', '.join(updates)}
                WHERE id_residente = %s AND id_residencia = %s
                RETURNING id_residente
            """
            
            cursor.execute(query, valores)
            
            # Si se actualizó costo_habitacion o el residente no tiene cobro previsto, generar cobro del mes siguiente
            costo_habitacion = data.get('costo_habitacion')
            id_residencia_final = data.get('id_residencia', id_residencia_actual)
            
            # Obtener el costo_habitacion actualizado o el existente
            cursor.execute("""
                SELECT costo_habitacion, metodo_pago_preferido FROM residente
                WHERE id_residente = %s
            """, (id_residente,))
            residente_actualizado = cursor.fetchone()
            costo_actual = float(residente_actualizado[0]) if residente_actualizado and residente_actualizado[0] else None
            metodo_pago_actual = residente_actualizado[1] if residente_actualizado else None
            
            # Generar cobro del mes siguiente si:
            # 1. Tiene costo_habitacion > 0
            # 2. No tiene ya un cobro previsto para el mes siguiente
            if costo_actual and costo_actual > 0:
                try:
                    # Calcular mes siguiente
                    hoy = datetime.now()
                    if hoy.month == 12:
                        siguiente_mes = datetime(hoy.year + 1, 1, 1)
                    else:
                        siguiente_mes = datetime(hoy.year, hoy.month + 1, 1)
                    
                    mes_siguiente_str = siguiente_mes.strftime('%Y-%m')
                    fecha_prevista = siguiente_mes.date()  # Día 1 del mes siguiente
                    
                    # Verificar si ya existe un cobro para el mes siguiente con concepto "Pago [mes]"
                    # Prevenir duplicados: no puede haber dos cobros con concepto "Pago [mes]" para el mismo residente y mes
                    cursor.execute("""
                        SELECT id_pago FROM pago_residente
                        WHERE id_residente = %s 
                          AND id_residencia = %s
                          AND mes_pagado = %s
                          AND (concepto ILIKE 'enero %%' OR concepto ILIKE 'febrero %%' OR concepto ILIKE 'marzo %%' 
                               OR concepto ILIKE 'abril %%' OR concepto ILIKE 'mayo %%' OR concepto ILIKE 'junio %%'
                               OR concepto ILIKE 'julio %%' OR concepto ILIKE 'agosto %%' OR concepto ILIKE 'septiembre %%'
                               OR concepto ILIKE 'octubre %%' OR concepto ILIKE 'noviembre %%' OR concepto ILIKE 'diciembre %%'
                               OR concepto ILIKE 'Pago %%')
                    """, (id_residente, id_residencia_final, mes_siguiente_str))
                    
                    if not cursor.fetchone():
                        # Crear el cobro previsto para el mes siguiente
                        meses_espanol = {
                            1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril',
                            5: 'mayo', 6: 'junio', 7: 'julio', 8: 'agosto',
                            9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'
                        }
                        nombre_mes = meses_espanol.get(siguiente_mes.month, 'mes')
                        # Formato: "Diciembre 25", "Enero 26" (solo mes y año corto, sin "Pago")
                    año_corto = str(siguiente_mes.year)[-2:]  # Últimos 2 dígitos
                    concepto = f"{nombre_mes.capitalize()} {año_corto}"
                        metodo_pago = metodo_pago_actual or 'transferencia'
                        
                        cursor.execute("""
                            INSERT INTO pago_residente (
                                id_residente, id_residencia, monto, fecha_pago, fecha_prevista,
                                mes_pagado, concepto, metodo_pago, estado, es_cobro_previsto
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            id_residente,
                            id_residencia_final,
                            costo_actual,
                            None,  # fecha_pago es NULL para cobros previstos
                            fecha_prevista,
                            mes_siguiente_str,
                            concepto,
                            metodo_pago,
                            'pendiente',
                            True
                        ))
                        app.logger.info(f"Cobro previsto generado automáticamente para residente actualizado (ID: {id_residente}): €{costo_actual}, mes: {mes_siguiente_str}")
                except Exception as e:
                    app.logger.error(f"Error al generar cobro previsto automático para residente actualizado {id_residente}: {str(e)}")
                    # No fallar la actualización del residente si falla la generación del cobro
            
            conn.commit()
            
            return jsonify({'mensaje': 'Residente actualizado exitosamente'}), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al actualizar residente: {str(e)}")
            return jsonify({'error': 'Error al actualizar residente'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# ============================================================================
# ENDPOINTS DE FACTURACIÓN - COBROS PREVISTOS DE RESIDENTES
# ============================================================================

@app.route('/api/v1/facturacion/cobros', methods=['GET'])
def listar_cobros():
    """
    Lista los cobros del período cercano (Facturación):
    - Todos los cobros pendientes
    - El último cobro completado de cada residente
    - Cobros completados del mes actual y mes anterior
    - Todo lo demás va a Históricos
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Calcular fechas de referencia
            hoy = datetime.now()
            mes_actual_inicio = datetime(hoy.year, hoy.month, 1).date()
            mes_anterior_inicio = (mes_actual_inicio - timedelta(days=1)).replace(day=1)
            
            # Construir filtro de residencias
            where_clause, params = build_residencia_filter('p.', 'id_residencia')
            
            # NUEVA LÓGICA: Filtrar solo período cercano
            # 1. Todos los cobros pendientes
            # 2. Último cobro completado de cada residente
            # 3. Cobros completados del mes actual y mes anterior
            
            # Guardar la query para poder reutilizarla después de generar cobros pendientes
            query = None
            params_query = None
            
            if where_clause:
                # Usuario normal: filtrar por residencias asignadas
                # where_clause ya incluye "WHERE", así que lo usamos directamente
                # Usar subquery para DISTINCT ON ya que no puede estar directamente en UNION ALL
                query = f"""
                    WITH cobros_pendientes AS (
                        -- Todos los cobros pendientes
                        SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                               p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                               p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion,
                               res.id_residencia, res.nombre as nombre_residencia,
                               1 as orden_prioridad
                        FROM pago_residente p
                        JOIN residente r ON p.id_residente = r.id_residente
                        JOIN residencia res ON p.id_residencia = res.id_residencia
                        {where_clause}
                          AND p.estado = 'pendiente'
                    ),
                    ultimos_cobros_completados AS (
                        -- Último cobro completado de cada residente
                        SELECT DISTINCT ON (p.id_residente)
                               p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                               p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                               p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion,
                               res.id_residencia, res.nombre as nombre_residencia,
                               2 as orden_prioridad
                        FROM pago_residente p
                        JOIN residente r ON p.id_residente = r.id_residente
                        JOIN residencia res ON p.id_residencia = res.id_residencia
                        {where_clause}
                          AND p.estado = 'cobrado'
                          AND p.fecha_pago IS NOT NULL
                        ORDER BY p.id_residente, p.fecha_pago DESC, p.fecha_creacion DESC
                    ),
                    cobros_mes_actual_anterior AS (
                        -- Cobros completados del mes actual y mes anterior
                        SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                               p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                               p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion,
                               res.id_residencia, res.nombre as nombre_residencia,
                               3 as orden_prioridad
                        FROM pago_residente p
                        JOIN residente r ON p.id_residente = r.id_residente
                        JOIN residencia res ON p.id_residencia = res.id_residencia
                        {where_clause}
                          AND p.estado = 'cobrado'
                          AND p.fecha_pago IS NOT NULL
                          AND p.fecha_pago >= %s
                    ),
                    cobros_periodo_cercano AS (
                        SELECT * FROM cobros_pendientes
                        UNION
                        SELECT * FROM ultimos_cobros_completados
                        UNION
                        SELECT * FROM cobros_mes_actual_anterior
                    ),
                    cobros_sin_duplicados AS (
                        SELECT DISTINCT ON (id_pago) * FROM cobros_periodo_cercano
                        ORDER BY id_pago
                    )
                    SELECT * FROM cobros_sin_duplicados
                    ORDER BY id_residencia, orden_prioridad,
                             CASE 
                                 WHEN fecha_prevista IS NOT NULL THEN fecha_prevista
                                 WHEN fecha_pago IS NOT NULL THEN fecha_pago
                                 ELSE '9999-12-31'::date
                             END ASC,
                             fecha_creacion DESC
                """
                # Agregar fecha del mes anterior a los params (necesitamos params para cada CTE)
                params_extended = list(params) * 3 + [mes_anterior_inicio]
                params_query = params_extended  # Guardar params para reutilizar
                cursor.execute(query, params_extended)
            else:
                # Super admin: sin filtro (acceso total)
                query = """
                    WITH cobros_pendientes AS (
                        -- Todos los cobros pendientes
                        SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                               p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                               p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion,
                               res.id_residencia, res.nombre as nombre_residencia,
                               1 as orden_prioridad
                        FROM pago_residente p
                        JOIN residente r ON p.id_residente = r.id_residente
                        JOIN residencia res ON p.id_residencia = res.id_residencia
                        WHERE p.estado = 'pendiente'
                    ),
                    ultimos_cobros_completados AS (
                        -- Último cobro completado de cada residente
                        SELECT DISTINCT ON (p.id_residente)
                               p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                               p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                               p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion,
                               res.id_residencia, res.nombre as nombre_residencia,
                               2 as orden_prioridad
                        FROM pago_residente p
                        JOIN residente r ON p.id_residente = r.id_residente
                        JOIN residencia res ON p.id_residencia = res.id_residencia
                        WHERE p.estado = 'cobrado'
                          AND p.fecha_pago IS NOT NULL
                        ORDER BY p.id_residente, p.fecha_pago DESC, p.fecha_creacion DESC
                    ),
                    cobros_mes_actual_anterior AS (
                        -- Cobros completados del mes actual y mes anterior
                        SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                               p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                               p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion,
                               res.id_residencia, res.nombre as nombre_residencia,
                               3 as orden_prioridad
                        FROM pago_residente p
                        JOIN residente r ON p.id_residente = r.id_residente
                        JOIN residencia res ON p.id_residencia = res.id_residencia
                        WHERE p.estado = 'cobrado'
                          AND p.fecha_pago IS NOT NULL
                          AND p.fecha_pago >= %s
                    ),
                    cobros_periodo_cercano AS (
                        SELECT * FROM cobros_pendientes
                        UNION
                        SELECT * FROM ultimos_cobros_completados
                        UNION
                        SELECT * FROM cobros_mes_actual_anterior
                    )
                    SELECT DISTINCT ON (id_pago) * FROM cobros_periodo_cercano
                    ORDER BY id_pago
                """
                params_extended = [mes_anterior_inicio]
                params_query = params_extended  # Guardar params para reutilizar
                cursor.execute(query, params_extended)
            
            cobros = cursor.fetchall()
            
            # NUEVA LÓGICA: Generar automáticamente cobros pendientes para el mes siguiente
            # si un residente tiene cobros completados pero no tiene cobro pendiente
            # Calcular mes siguiente
            hoy = datetime.now()
            if hoy.month == 12:
                siguiente_mes = datetime(hoy.year + 1, 1, 1)
            else:
                siguiente_mes = datetime(hoy.year, hoy.month + 1, 1)
            mes_siguiente_str = siguiente_mes.strftime('%Y-%m')
            fecha_prevista = siguiente_mes.date()
            
            meses_espanol = {
                1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril',
                5: 'mayo', 6: 'junio', 7: 'julio', 8: 'agosto',
                9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'
            }
            nombre_mes = meses_espanol.get(siguiente_mes.month, 'mes')
            # Formato: "Diciembre 25", "Enero 26" (solo mes y año corto, sin "Pago")
            año_corto = str(siguiente_mes.year)[-2:]  # Últimos 2 dígitos
            concepto_siguiente = f"{nombre_mes.capitalize()} {año_corto}"
            
            # Identificar residentes con cobros completados pero sin cobro pendiente para el mes siguiente
            # Obtener residentes activos con costo_habitacion que tienen cobros completados
            if where_clause:
                # Usuario normal: filtrar por residencias asignadas
                # Construir filtro para residente (donde clause tiene formato "WHERE p.id_residencia IN (...)")
                # Necesitamos extraer los IDs de residencia de params
                if params:
                    placeholders = ','.join(['%s'] * len(params))
                    query_residentes = f"""
                        SELECT DISTINCT r.id_residente, r.id_residencia, r.costo_habitacion, 
                               r.metodo_pago_preferido, r.nombre, r.apellido
                        FROM residente r
                        JOIN pago_residente p ON r.id_residente = p.id_residente
                        WHERE r.activo = TRUE
                          AND r.costo_habitacion IS NOT NULL
                          AND r.costo_habitacion > 0
                          AND p.estado = 'cobrado'
                          AND p.fecha_pago IS NOT NULL
                          AND r.id_residencia IN ({placeholders})
                          AND NOT EXISTS (
                              SELECT 1 FROM pago_residente p2
                              WHERE p2.id_residente = r.id_residente
                                AND p2.id_residencia = r.id_residencia
                                AND p2.mes_pagado = %s
                                AND (p2.concepto ILIKE 'enero %%' OR p2.concepto ILIKE 'febrero %%' OR p2.concepto ILIKE 'marzo %%' 
                                     OR p2.concepto ILIKE 'abril %%' OR p2.concepto ILIKE 'mayo %%' OR p2.concepto ILIKE 'junio %%'
                                     OR p2.concepto ILIKE 'julio %%' OR p2.concepto ILIKE 'agosto %%' OR p2.concepto ILIKE 'septiembre %%'
                                     OR p2.concepto ILIKE 'octubre %%' OR p2.concepto ILIKE 'noviembre %%' OR p2.concepto ILIKE 'diciembre %%'
                                     OR p2.concepto ILIKE 'Pago %%')
                          )
                    """
                    cursor.execute(query_residentes, list(params) + [mes_siguiente_str])
                else:
                    residentes_sin_cobro_pendiente = []
            else:
                # Super admin: sin filtro
                query_residentes = """
                    SELECT DISTINCT r.id_residente, r.id_residencia, r.costo_habitacion, 
                           r.metodo_pago_preferido, r.nombre, r.apellido
                    FROM residente r
                    JOIN pago_residente p ON r.id_residente = p.id_residente
                    WHERE r.activo = TRUE
                      AND r.costo_habitacion IS NOT NULL
                      AND r.costo_habitacion > 0
                      AND p.estado = 'cobrado'
                      AND p.fecha_pago IS NOT NULL
                      AND NOT EXISTS (
                          SELECT 1 FROM pago_residente p2
                          WHERE p2.id_residente = r.id_residente
                            AND p2.id_residencia = r.id_residencia
                            AND p2.mes_pagado = %s
                            AND p2.concepto ILIKE 'Pago %%'
                      )
                """
                cursor.execute(query_residentes, [mes_siguiente_str])
                residentes_sin_cobro_pendiente = cursor.fetchall()
            
            # Generar cobros pendientes faltantes
            cobros_generados = 0
            for res in residentes_sin_cobro_pendiente:
                id_residente = res[0]
                id_residencia = res[1]
                costo_habitacion = float(res[2])
                metodo_pago = res[3] or 'transferencia'
                nombre = res[4]
                apellido = res[5]
                
                try:
                    cursor.execute("""
                        INSERT INTO pago_residente (
                            id_residente, id_residencia, monto, fecha_pago, fecha_prevista,
                            mes_pagado, concepto, metodo_pago, estado, es_cobro_previsto
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id_pago
                    """, (
                        id_residente,
                        id_residencia,
                        costo_habitacion,
                        None,  # fecha_pago es NULL para cobros previstos
                        fecha_prevista,
                        mes_siguiente_str,
                        concepto_siguiente,
                        metodo_pago,
                        'pendiente',
                        True
                    ))
                    cobros_generados += 1
                    app.logger.info(f"Cobro pendiente generado automáticamente para {nombre} {apellido} (ID: {id_residente}): €{costo_habitacion}, mes: {mes_siguiente_str}")
                except Exception as e:
                    app.logger.error(f"Error al generar cobro pendiente automático para residente {id_residente}: {str(e)}")
            
            # Si se generaron cobros, volver a consultar para incluirlos
            if cobros_generados > 0:
                conn.commit()
                # Volver a ejecutar la query original para incluir los nuevos cobros pendientes
                if query and params_query:
                    cursor.execute(query, params_query)
                    cobros = cursor.fetchall()
            
            # Agrupar por residencia
            cobros_por_residencia = {}
            for cobro in cobros:
                idx_residencia = 13
                idx_nombre_residencia = 14
                
                id_residencia = cobro[idx_residencia]
                nombre_residencia = cobro[idx_nombre_residencia] if len(cobro) > idx_nombre_residencia else f"Residencia {id_residencia}"
                
                if id_residencia not in cobros_por_residencia:
                    cobros_por_residencia[id_residencia] = {
                        'id_residencia': id_residencia,
                        'nombre_residencia': nombre_residencia,
                        'cobros': []
                    }
                
                cobros_por_residencia[id_residencia]['cobros'].append({
                    'id_pago': cobro[0],
                    'id_residente': cobro[1],
                    'residente': cobro[2],
                    'monto': float(cobro[3]),
                    'fecha_pago': str(cobro[4]) if cobro[4] else None,
                    'fecha_prevista': str(cobro[5]) if cobro[5] else None,
                    'mes_pagado': cobro[6],
                    'concepto': cobro[7],
                    'metodo_pago': cobro[8],
                    'estado': cobro[9],
                    'es_cobro_previsto': cobro[10],
                    'observaciones': cobro[11],
                    'fecha_creacion': cobro[12].isoformat() if cobro[12] else None,
                    'nombre_residencia': nombre_residencia
                })
            
            # Convertir a lista ordenada por id_residencia
            resultado_agrupado = list(cobros_por_residencia.values())
            resultado_agrupado.sort(key=lambda x: x['id_residencia'])
            
            return jsonify({
                'cobros': [c for grupo in resultado_agrupado for c in grupo['cobros']],  # Lista plana para compatibilidad
                'cobros_agrupados': resultado_agrupado,  # Estructura agrupada
                'total': len(cobros)
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar pagos: {str(e)}")
        return jsonify({'error': 'Error al obtener pagos'}), 500


@app.route('/api/v1/facturacion/cobros', methods=['POST'])
def crear_cobro():
    """Crea un cobro previsto o registra un cobro realizado."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        # Validar datos con el módulo de validación
        is_valid, errors = validate_cobro_data(data, is_update=False)
        if not is_valid:
            return jsonify({'error': 'Errores de validación', 'detalles': errors}), 400
        
        id_residente = data.get('id_residente')
        monto = data.get('monto')
        fecha_prevista = data.get('fecha_prevista')
        fecha_pago = data.get('fecha_pago')
        
        # Determinar automáticamente si es cobro previsto: si NO tiene fecha_pago, es previsto
        es_cobro_previsto = data.get('es_cobro_previsto')
        if es_cobro_previsto is None:
            es_cobro_previsto = not fecha_pago or fecha_pago == ''
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el residente existe y obtener su residencia
            cursor.execute("""
                SELECT id_residente, id_residencia FROM residente
                WHERE id_residente = %s
            """, (id_residente,))
            
            residente_data = cursor.fetchone()
            if not residente_data:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            residente_id_residencia = residente_data[1]
            
            # Verificar que el usuario tiene acceso a la residencia del residente
            is_valid, error_response = validate_residencia_access(residente_id_residencia)
            if not is_valid:
                return error_response
            
            # Usar la residencia del residente (no la del usuario) para el cobro
            id_residencia_cobro = residente_id_residencia
            
            # Determinar estado: si tiene fecha_pago, es cobrado; si no, es pendiente
            estado_final = data.get('estado')
            if not estado_final:
                if fecha_pago:
                    estado_final = 'cobrado'
                else:
                    estado_final = 'pendiente'
            
            # Convertir "Pago mensual habitación" a formato "Pago [Mes] [Año]" basándose en fecha_prevista o mes_pagado
            concepto = data.get('concepto', '')
            mes_pagado = data.get('mes_pagado')
            fecha_prevista = data.get('fecha_prevista')
            
            if concepto and concepto.strip() == 'Pago mensual habitación':
                meses_espanol = {
                    1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril',
                    5: 'mayo', 6: 'junio', 7: 'julio', 8: 'agosto',
                    9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'
                }
                
                mes = None
                año = None
                
                if mes_pagado:
                    # mes_pagado está en formato 'YYYY-MM'
                    partes = mes_pagado.split('-')
                    if len(partes) == 2:
                        año = int(partes[0])
                        mes = int(partes[1])
                elif fecha_prevista:
                    # fecha_prevista puede ser string ISO o date
                    if isinstance(fecha_prevista, str):
                        try:
                            fecha = datetime.strptime(fecha_prevista, '%Y-%m-%d')
                            año = fecha.year
                            mes = fecha.month
                        except:
                            pass
                    else:
                        año = fecha_prevista.year
                        mes = fecha_prevista.month
                
                if mes and año:
                    nombre_mes = meses_espanol.get(mes, 'mes')
                    # Formato: "Diciembre 25", "Enero 26" (solo mes y año corto, sin "Pago")
                    año_corto = str(año)[-2:]  # Últimos 2 dígitos
                    concepto = f"{nombre_mes.capitalize()} {año_corto}"
            
            # Prevenir duplicados: Si el concepto es un mes (pago mensual de habitación), verificar que no exista otro cobro
            # con el mismo id_residente, mes_pagado y concepto de mes
            meses_espanol_list = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 
                                  'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre']
            es_concepto_mensual = concepto and any(concepto.lower().startswith(mes) for mes in meses_espanol_list)
            if es_concepto_mensual and mes_pagado:
                cursor.execute("""
                    SELECT id_pago FROM pago_residente
                    WHERE id_residente = %s 
                      AND id_residencia = %s
                      AND mes_pagado = %s
                      AND (concepto ILIKE 'enero %%' OR concepto ILIKE 'febrero %%' OR concepto ILIKE 'marzo %%' 
                           OR concepto ILIKE 'abril %%' OR concepto ILIKE 'mayo %%' OR concepto ILIKE 'junio %%'
                           OR concepto ILIKE 'julio %%' OR concepto ILIKE 'agosto %%' OR concepto ILIKE 'septiembre %%'
                           OR concepto ILIKE 'octubre %%' OR concepto ILIKE 'noviembre %%' OR concepto ILIKE 'diciembre %%'
                           OR concepto ILIKE 'Pago %%')
                """, (id_residente, id_residencia_cobro, mes_pagado))
                
                cobro_duplicado = cursor.fetchone()
                if cobro_duplicado:
                    return jsonify({
                        'error': f'Ya existe un cobro de habitación para este residente en el mes {mes_pagado}. No se pueden crear cobros duplicados con concepto de mes.'
                    }), 400
            
            cursor.execute("""
                INSERT INTO pago_residente (id_residente, id_residencia, monto, fecha_pago, fecha_prevista,
                                          mes_pagado, concepto, metodo_pago, estado, es_cobro_previsto, observaciones)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_pago
            """, (
                id_residente,
                id_residencia_cobro,
                monto,
                fecha_pago,  # Permitir fecha_pago siempre que se proporcione
                fecha_prevista,  # Permitir fecha_prevista siempre que se proporcione
                data.get('mes_pagado'),
                data.get('concepto'),
                data.get('metodo_pago'),
                estado_final,
                es_cobro_previsto,
                data.get('observaciones')
            ))
            
            id_pago = cursor.fetchone()[0]
            conn.commit()
            
            return jsonify({
                'id_pago': id_pago,
                'mensaje': 'Cobro previsto registrado exitosamente' if es_cobro_previsto else 'Cobro registrado exitosamente'
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear cobro: {str(e)}")
            return jsonify({'error': 'Error al crear cobro'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/facturacion/cobros/generar-previstos', methods=['POST'])
def generar_cobros_previstos():
    """
    Genera automáticamente cobros previstos para el MES SIGUIENTE para todos los residentes activos
    que tengan costo_habitacion definido.
    
    NUEVA LÓGICA:
    - Solo genera el cobro del mes siguiente (no histórico)
    - Se cobra por adelantado el mes
    - Fecha prevista: día 1 del mes siguiente
    - Si el residente ya tiene un cobro (completado o previsto) para el mes siguiente, no se genera
    
    Para generar cobros históricos (desde fecha_ingreso), usar el endpoint generar-historicos.
    """
    try:
        data = request.get_json() or {}
        mes_referencia = data.get('mes')  # Formato: 'YYYY-MM', opcional
        año_referencia = data.get('año')  # Opcional
        
        # Si no se especifica mes, usar el mes ACTUAL (no el siguiente)
        if mes_referencia:
            try:
                fecha_base = datetime.strptime(f"{mes_referencia}-01", "%Y-%m-%d")
            except:
                return jsonify({'error': 'Formato de mes inválido. Use YYYY-MM'}), 400
        else:
            # Mes ACTUAL por defecto (cambiar lógica: generar para mes actual si no hay cobro completado)
            hoy = datetime.now()
            fecha_base = datetime(hoy.year, hoy.month, 1)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Calcular mes siguiente
            hoy = datetime.now()
            if hoy.month == 12:
                siguiente_mes = datetime(hoy.year + 1, 1, 1)
            else:
                siguiente_mes = datetime(hoy.year, hoy.month + 1, 1)
            mes_siguiente = siguiente_mes.strftime('%Y-%m')
            
            # Limpiar TODOS los cobros previstos pendientes antes de regenerar
            # Si es super_admin, limpia de TODAS las residencias. Si no, solo de las asignadas.
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                cursor.execute("""
                    DELETE FROM pago_residente
                    WHERE es_cobro_previsto = TRUE
                      AND estado = 'pendiente'
                """)
            else:
                # Usuario normal: limpiar solo de sus residencias asignadas
                if not g.residencias_acceso:
                    return jsonify({'error': 'Usuario sin residencias asignadas'}), 403
                
                placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                cursor.execute(f"""
                    DELETE FROM pago_residente
                    WHERE id_residencia IN ({placeholders})
                      AND es_cobro_previsto = TRUE
                      AND estado = 'pendiente'
                """, tuple(g.residencias_acceso))
            
            cobros_eliminados = cursor.rowcount
            
            # Calcular mes siguiente (una sola vez)
            hoy = datetime.now()
            mes_actual = hoy.month
            año_actual = hoy.year
            
            if mes_actual == 12:
                siguiente_mes = datetime(año_actual + 1, 1, 1)
            else:
                siguiente_mes = datetime(año_actual, mes_actual + 1, 1)
            
            mes_siguiente_str = siguiente_mes.strftime('%Y-%m')
            fecha_prevista = siguiente_mes.date()  # Día 1 del mes siguiente
            
            # Obtener residentes activos con costo_habitacion
            # Si es super_admin, obtiene de TODAS las residencias. Si no, solo de las asignadas.
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                cursor.execute("""
                    SELECT id_residente, nombre, apellido, costo_habitacion, metodo_pago_preferido, fecha_ingreso, id_residencia
                    FROM residente
                    WHERE activo = TRUE 
                      AND costo_habitacion IS NOT NULL 
                      AND costo_habitacion > 0
                      AND fecha_ingreso IS NOT NULL
                """)
                cursor.execute("SELECT COUNT(*) FROM residente WHERE activo = TRUE")
                total_residentes_activos = cursor.fetchone()[0]
                app.logger.info(f"Generando cobros previstos GLOBAL (Super Admin) para mes siguiente: {mes_siguiente_str}")
            else:
                # Usuario normal: filtrar por residencias asignadas
                if not g.residencias_acceso:
                    return jsonify({'error': 'Usuario sin residencias asignadas'}), 403
                
                placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                cursor.execute(f"""
                    SELECT id_residente, nombre, apellido, costo_habitacion, metodo_pago_preferido, fecha_ingreso, id_residencia
                    FROM residente
                    WHERE id_residencia IN ({placeholders})
                      AND activo = TRUE 
                      AND costo_habitacion IS NOT NULL 
                      AND costo_habitacion > 0
                      AND fecha_ingreso IS NOT NULL
                """, tuple(g.residencias_acceso))
                
                cursor.execute(f"SELECT COUNT(*) FROM residente WHERE id_residencia IN ({placeholders}) AND activo = TRUE", tuple(g.residencias_acceso))
                total_residentes_activos = cursor.fetchone()[0]
                app.logger.info(f"Generando cobros previstos para residencias: {g.residencias_acceso}, mes siguiente: {mes_siguiente_str}")
            
            residentes = cursor.fetchall()

            app.logger.info(f"Total residentes activos en alcance: {total_residentes_activos}")
            app.logger.info(f"Residentes candidatos encontrados (con costo y fecha_ingreso): {len(residentes)}")
            app.logger.info(f"Mes siguiente a generar: {mes_siguiente_str}")
            
            if not residentes:
                return jsonify({
                    'mensaje': 'No hay residentes activos con costo_habitacion definido que deban tener cobros previstos',
                    'cobros_generados': 0,
                    'cobros_eliminados': cobros_eliminados,
                    'mes_referencia': mes_siguiente_str,
                    'total_residentes_activos': total_residentes_activos,
                    'residentes_candidatos': 0
                }), 200
            
            cobros_generados = 0
            cobros_duplicados = 0
            cobros_ya_existentes = 0
            errores = []
            residentes_procesados = []
            
            meses_espanol = {
                1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril',
                5: 'mayo', 6: 'junio', 7: 'julio', 8: 'agosto',
                9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'
            }
            
            # NUEVA LÓGICA: Solo generar cobro para el mes siguiente
            for residente in residentes:
                id_residente = residente[0]
                nombre = residente[1]
                apellido = residente[2]
                costo_habitacion = float(residente[3])
                metodo_pago = residente[4] or 'transferencia'  # Por defecto transferencia
                fecha_ingreso = residente[5]  # fecha_ingreso del residente
                residencia_del_residente = residente[6] # ID de la residencia del residente actual
                
                if not fecha_ingreso:
                    app.logger.warning(f"Residente {nombre} {apellido} (ID: {id_residente}) no tiene fecha_ingreso, saltando")
                    continue
                
                # Verificar si ya existe un cobro (completado o previsto) para el mes siguiente con concepto "Pago [mes]"
                # Prevenir duplicados: no puede haber dos cobros con concepto "Pago [mes]" para el mismo residente y mes
                cursor.execute("""
                    SELECT id_pago, estado FROM pago_residente
                    WHERE id_residente = %s 
                      AND id_residencia = %s
                      AND mes_pagado = %s
                      AND (concepto ILIKE 'enero %%' OR concepto ILIKE 'febrero %%' OR concepto ILIKE 'marzo %%' 
                           OR concepto ILIKE 'abril %%' OR concepto ILIKE 'mayo %%' OR concepto ILIKE 'junio %%'
                           OR concepto ILIKE 'julio %%' OR concepto ILIKE 'agosto %%' OR concepto ILIKE 'septiembre %%'
                           OR concepto ILIKE 'octubre %%' OR concepto ILIKE 'noviembre %%' OR concepto ILIKE 'diciembre %%'
                           OR concepto ILIKE 'Pago %%')
                """, (id_residente, residencia_del_residente, mes_siguiente_str))
                
                cobro_existente = cursor.fetchone()
                
                if cobro_existente:
                    # Ya existe un cobro para el mes siguiente
                    if cobro_existente[1] == 'cobrado':
                        cobros_ya_existentes += 1
                        app.logger.debug(f"Residente {nombre} {apellido} (ID: {id_residente}) ya tiene cobro completado para {mes_siguiente_str}")
                    else:
                        cobros_duplicados += 1
                        app.logger.debug(f"Residente {nombre} {apellido} (ID: {id_residente}) ya tiene cobro previsto para {mes_siguiente_str}")
                    continue
                
                # Generar concepto con el nombre del mes
                nombre_mes = meses_espanol.get(siguiente_mes.month, 'mes')
                concepto = f"Pago {nombre_mes} {siguiente_mes.year}"
                
                # Crear el cobro previsto para el mes siguiente
                try:
                    cursor.execute("""
                        INSERT INTO pago_residente (
                            id_residente, id_residencia, monto, fecha_pago, fecha_prevista,
                            mes_pagado, concepto, metodo_pago, estado, es_cobro_previsto
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id_pago
                    """, (
                        id_residente,
                        residencia_del_residente,
                        costo_habitacion,
                        None,  # fecha_pago es NULL para cobros previstos
                        fecha_prevista,  # Día 1 del mes siguiente
                        mes_siguiente_str,
                        concepto,
                        metodo_pago,
                        'pendiente',
                        True
                    ))
                    
                    cobros_generados += 1
                    app.logger.info(f"Cobro previsto generado para {nombre} {apellido} (ID: {id_residente}): €{costo_habitacion}, mes: {mes_siguiente_str}")
                    residentes_procesados.append(f"{nombre} {apellido} (ID: {id_residente})")
                    
                except Exception as e:
                    errores.append(f"Error al crear cobro para {nombre} {apellido} mes {mes_siguiente_str}: {str(e)}")
                    app.logger.error(f"Error al crear cobro previsto para residente {id_residente} mes {mes_siguiente_str}: {str(e)}")
            
            conn.commit()
            
            resultado = {
                'mensaje': f'Cobros previstos generados exitosamente para el mes siguiente ({mes_siguiente_str})',
                'cobros_generados': cobros_generados,
                'cobros_eliminados': cobros_eliminados,
                'cobros_duplicados': cobros_duplicados,
                'cobros_ya_existentes': cobros_ya_existentes,
                'mes_actual': mes_actual.strftime('%Y-%m'),
                'total_residentes_procesados': len(residentes),
                'total_residentes_candidatos': len(residentes),
                'residentes_procesados': residentes_procesados
            }
            
            app.logger.info(f"Resumen: {cobros_generados} cobros generados, {cobros_duplicados} duplicados (previstos), {cobros_ya_existentes} ya existentes (cobrados), {len(residentes)} residentes procesados")
            
            if errores:
                resultado['errores'] = errores
            
            return jsonify(resultado), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al generar cobros previstos: {str(e)}")
            return jsonify({'error': f'Error al generar cobros previstos: {str(e)}'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/facturacion/cobros/estadisticas', methods=['GET'])
def estadisticas_cobros():
    """Obtiene estadísticas mensuales de cobros (histórico y estimaciones)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Si es Admin (rol 1), obtiene de TODAS las residencias agrupado. Si no, solo de la suya.
            if g.id_rol == 1:
                # Obtener cobros históricos (cobrados) agrupados por mes y residencia
                cursor.execute("""
                    SELECT 
                        CASE 
                            WHEN p.metodo_pago ILIKE 'remesa' 
                                 AND EXTRACT(DAY FROM p.fecha_pago) = 30 
                                 AND p.mes_pagado IS NOT NULL
                            THEN p.mes_pagado
                            ELSE TO_CHAR(p.fecha_pago, 'YYYY-MM')
                        END as mes,
                        res.nombre as nombre_residencia,
                        res.id_residencia,
                        SUM(p.monto) as total_cobrado,
                        COUNT(*) as cantidad
                    FROM pago_residente p
                    JOIN residencia res ON p.id_residencia = res.id_residencia
                    WHERE p.estado = 'cobrado'
                      AND p.fecha_pago IS NOT NULL
                    GROUP BY 
                        CASE 
                            WHEN p.metodo_pago ILIKE 'remesa' 
                                 AND EXTRACT(DAY FROM p.fecha_pago) = 30 
                                 AND p.mes_pagado IS NOT NULL
                            THEN p.mes_pagado
                            ELSE TO_CHAR(p.fecha_pago, 'YYYY-MM')
                        END,
                        res.id_residencia, res.nombre
                    ORDER BY mes DESC
                    LIMIT 48
                """)
                historico = cursor.fetchall()
                
                # Obtener estimaciones futuras agrupados por mes y residencia
                cursor.execute("""
                    SELECT 
                        CASE 
                            WHEN p.metodo_pago ILIKE 'remesa' AND p.mes_pagado IS NOT NULL
                            THEN p.mes_pagado
                            ELSE TO_CHAR(p.fecha_prevista, 'YYYY-MM')
                        END as mes,
                        res.nombre as nombre_residencia,
                        res.id_residencia,
                        SUM(p.monto) as total_previsto,
                        COUNT(*) as cantidad
                    FROM pago_residente p
                    JOIN residencia res ON p.id_residencia = res.id_residencia
                    WHERE p.es_cobro_previsto = TRUE
                      AND p.estado = 'pendiente'
                      AND p.fecha_prevista IS NOT NULL
                    GROUP BY 
                        CASE 
                            WHEN p.metodo_pago ILIKE 'remesa' AND p.mes_pagado IS NOT NULL
                            THEN p.mes_pagado
                            ELSE TO_CHAR(p.fecha_prevista, 'YYYY-MM')
                        END,
                        res.id_residencia, res.nombre
                    ORDER BY mes ASC
                    LIMIT 24
                """)
                estimaciones = cursor.fetchall()

                historico_data = []
                for row in historico:
                    historico_data.append({
                        'mes': row[0],
                        'nombre_residencia': row[1],
                        'id_residencia': row[2],
                        'total': float(row[3]),
                        'cantidad': row[4]
                    })

                estimaciones_data = []
                for row in estimaciones:
                    estimaciones_data.append({
                        'mes': row[0],
                        'nombre_residencia': row[1],
                        'id_residencia': row[2],
                        'total': float(row[3]),
                        'cantidad': row[4]
                    })

            else:
                # Usuario normal: filtrar por residencias asignadas
                if not g.residencias_acceso:
                    return jsonify({'historico': [], 'estimaciones': []}), 200
                
                placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                
                # Obtener cobros históricos (cobrados) agrupados por mes
                cursor.execute(f"""
                    SELECT 
                        CASE 
                            WHEN metodo_pago ILIKE 'remesa' 
                                 AND EXTRACT(DAY FROM fecha_pago) = 30 
                                 AND mes_pagado IS NOT NULL
                            THEN mes_pagado
                            ELSE TO_CHAR(fecha_pago, 'YYYY-MM')
                        END as mes,
                        SUM(monto) as total_cobrado,
                        COUNT(*) as cantidad
                    FROM pago_residente
                    WHERE id_residencia IN ({placeholders})
                      AND estado = 'cobrado'
                      AND fecha_pago IS NOT NULL
                    GROUP BY 
                        CASE 
                            WHEN metodo_pago ILIKE 'remesa' 
                                 AND EXTRACT(DAY FROM fecha_pago) = 30 
                                 AND mes_pagado IS NOT NULL
                            THEN mes_pagado
                            ELSE TO_CHAR(fecha_pago, 'YYYY-MM')
                        END
                    ORDER BY mes DESC
                    LIMIT 12
                """, tuple(g.residencias_acceso))
                
                historico = cursor.fetchall()
                
                # Obtener estimaciones futuras
                cursor.execute(f"""
                    SELECT 
                        CASE 
                            WHEN metodo_pago ILIKE 'remesa' AND mes_pagado IS NOT NULL
                            THEN mes_pagado
                            ELSE TO_CHAR(fecha_prevista, 'YYYY-MM')
                        END as mes,
                        SUM(monto) as total_previsto,
                        COUNT(*) as cantidad
                    FROM pago_residente
                    WHERE id_residencia IN ({placeholders})
                      AND es_cobro_previsto = TRUE
                      AND estado = 'pendiente'
                      AND fecha_prevista IS NOT NULL
                    GROUP BY 
                        CASE 
                            WHEN metodo_pago ILIKE 'remesa' AND mes_pagado IS NOT NULL
                            THEN mes_pagado
                            ELSE TO_CHAR(fecha_prevista, 'YYYY-MM')
                        END
                    ORDER BY mes ASC
                    LIMIT 6
                """, tuple(g.residencias_acceso))
                
                estimaciones = cursor.fetchall()
                
                historico_data = []
                for row in historico:
                    historico_data.append({
                        'mes': row[0],
                        'total': float(row[1]),
                        'cantidad': row[2]
                    })
                
                estimaciones_data = []
                for row in estimaciones:
                    estimaciones_data.append({
                        'mes': row[0],
                        'total': float(row[1]),
                        'cantidad': row[2]
                    })
            
            return jsonify({
                'historico': historico_data,
                'estimaciones': estimaciones_data
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al obtener estadísticas: {str(e)}")
        return jsonify({'error': 'Error al obtener estadísticas'}), 500


@app.route('/api/v1/facturacion/cobros/ultimos-completados', methods=['GET'])
def ultimos_cobros_completados():
    """
    Obtiene el último pago mensual y el último pago extra completado de cada residente.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar qué columnas existen en la tabla pago_residente
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'pago_residente'
            """)
            columnas_existentes = {row[0] for row in cursor.fetchall()}
            
            # Construir SELECT dinámicamente según columnas existentes
            columnas_base = [
                'p.id_pago', 'p.id_residente', 
                "r.nombre || ' ' || r.apellido as residente",
                'p.monto', 'p.fecha_pago', 'p.fecha_prevista', 'p.mes_pagado', 'p.concepto',
                'p.metodo_pago', 'p.estado', 'p.es_cobro_previsto', 'p.fecha_creacion'
            ]
            
            if 'observaciones' in columnas_existentes:
                columnas_base.insert(-1, 'p.observaciones')
            else:
                columnas_base.insert(-1, 'NULL as observaciones')
            
            select_clause = ', '.join(columnas_base)
            
            # Obtener último pago mensual de cada residente
            # Consideramos "mensual" los que tienen concepto que empieza con "Pago" seguido de un mes
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                # Super admin: sin filtro
                query_mensual = f"""
                    SELECT DISTINCT ON (p.id_residente)
                        {select_clause}
                    FROM pago_residente p
                    JOIN residente r ON p.id_residente = r.id_residente
                    WHERE p.estado = 'cobrado'
                      AND p.fecha_pago IS NOT NULL
                      AND (p.concepto ILIKE 'enero %%' OR p.concepto ILIKE 'febrero %%' OR p.concepto ILIKE 'marzo %%' 
                           OR p.concepto ILIKE 'abril %%' OR p.concepto ILIKE 'mayo %%' OR p.concepto ILIKE 'junio %%'
                           OR p.concepto ILIKE 'julio %%' OR p.concepto ILIKE 'agosto %%' OR p.concepto ILIKE 'septiembre %%'
                           OR p.concepto ILIKE 'octubre %%' OR p.concepto ILIKE 'noviembre %%' OR p.concepto ILIKE 'diciembre %%'
                           OR p.concepto ILIKE 'Pago %%' OR p.concepto ILIKE 'Pago mensual%%')
                    ORDER BY p.id_residente, p.fecha_pago DESC, p.fecha_creacion DESC
                """
                cursor.execute(query_mensual)
                ultimos_mensuales = cursor.fetchall()
                
                query_extra = f"""
                    SELECT DISTINCT ON (p.id_residente)
                        {select_clause}
                    FROM pago_residente p
                    JOIN residente r ON p.id_residente = r.id_residente
                    WHERE p.estado = 'cobrado'
                      AND p.fecha_pago IS NOT NULL
                      AND (p.concepto IS NULL OR (p.concepto NOT ILIKE 'enero %%' AND p.concepto NOT ILIKE 'febrero %%' 
                           AND p.concepto NOT ILIKE 'marzo %%' AND p.concepto NOT ILIKE 'abril %%' 
                           AND p.concepto NOT ILIKE 'mayo %%' AND p.concepto NOT ILIKE 'junio %%'
                           AND p.concepto NOT ILIKE 'julio %%' AND p.concepto NOT ILIKE 'agosto %%' 
                           AND p.concepto NOT ILIKE 'septiembre %%' AND p.concepto NOT ILIKE 'octubre %%' 
                           AND p.concepto NOT ILIKE 'noviembre %%' AND p.concepto NOT ILIKE 'diciembre %%'
                           AND p.concepto NOT ILIKE 'Pago %%' AND p.concepto NOT ILIKE 'Pago mensual%%'))
                    ORDER BY p.id_residente, p.fecha_pago DESC, p.fecha_creacion DESC
                """
                cursor.execute(query_extra)
            else:
                # Usuario normal: filtrar por lista de residencias
                if not g.residencias_acceso:
                    return jsonify({'cobros': [], 'total': 0}), 200
                
                placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                
                query_mensual = f"""
                    SELECT DISTINCT ON (p.id_residente)
                        {select_clause}
                    FROM pago_residente p
                    JOIN residente r ON p.id_residente = r.id_residente
                    WHERE p.id_residencia IN ({placeholders})
                      AND p.estado = 'cobrado'
                      AND p.fecha_pago IS NOT NULL
                      AND (p.concepto ILIKE 'enero %%' OR p.concepto ILIKE 'febrero %%' OR p.concepto ILIKE 'marzo %%' 
                           OR p.concepto ILIKE 'abril %%' OR p.concepto ILIKE 'mayo %%' OR p.concepto ILIKE 'junio %%'
                           OR p.concepto ILIKE 'julio %%' OR p.concepto ILIKE 'agosto %%' OR p.concepto ILIKE 'septiembre %%'
                           OR p.concepto ILIKE 'octubre %%' OR p.concepto ILIKE 'noviembre %%' OR p.concepto ILIKE 'diciembre %%'
                           OR p.concepto ILIKE 'Pago %%' OR p.concepto ILIKE 'Pago mensual%%')
                    ORDER BY p.id_residente, p.fecha_pago DESC, p.fecha_creacion DESC
                """
                cursor.execute(query_mensual, tuple(g.residencias_acceso))
                ultimos_mensuales = cursor.fetchall()
                
                query_extra = f"""
                    SELECT DISTINCT ON (p.id_residente)
                        {select_clause}
                    FROM pago_residente p
                    JOIN residente r ON p.id_residente = r.id_residente
                    WHERE p.id_residencia IN ({placeholders})
                      AND p.estado = 'cobrado'
                      AND p.fecha_pago IS NOT NULL
                      AND (p.concepto IS NULL OR (p.concepto NOT ILIKE 'enero %%' AND p.concepto NOT ILIKE 'febrero %%' 
                           AND p.concepto NOT ILIKE 'marzo %%' AND p.concepto NOT ILIKE 'abril %%' 
                           AND p.concepto NOT ILIKE 'mayo %%' AND p.concepto NOT ILIKE 'junio %%'
                           AND p.concepto NOT ILIKE 'julio %%' AND p.concepto NOT ILIKE 'agosto %%' 
                           AND p.concepto NOT ILIKE 'septiembre %%' AND p.concepto NOT ILIKE 'octubre %%' 
                           AND p.concepto NOT ILIKE 'noviembre %%' AND p.concepto NOT ILIKE 'diciembre %%'
                           AND p.concepto NOT ILIKE 'Pago %%' AND p.concepto NOT ILIKE 'Pago mensual%%'))
                    ORDER BY p.id_residente, p.fecha_pago DESC, p.fecha_creacion DESC
                """
                cursor.execute(query_extra, tuple(g.residencias_acceso))
            
            ultimos_extras = cursor.fetchall()
            
            # Formatear resultados
            resultado = []
            
            # Determinar índices basados en si observaciones existe
            # Orden: id_pago(0), id_residente(1), residente(2), monto(3), fecha_pago(4), 
            # fecha_prevista(5), mes_pagado(6), concepto(7), metodo_pago(8), estado(9), 
            # es_cobro_previsto(10), observaciones(11 si existe), fecha_creacion(último)
            tiene_observaciones = 'observaciones' in columnas_existentes
            idx_fecha_creacion = 12 if tiene_observaciones else 11
            
            for cobro in ultimos_mensuales:
                try:
                    if len(cobro) < 11:
                        app.logger.warning(f"Cobro mensual con menos columnas de las esperadas: {len(cobro)}")
                        continue
                    
                    resultado.append({
                        'id_pago': cobro[0],
                        'id_residente': cobro[1],
                        'residente': cobro[2],
                        'monto': float(cobro[3]) if cobro[3] is not None else 0.0,
                        'fecha_pago': str(cobro[4]) if cobro[4] else None,
                        'fecha_prevista': str(cobro[5]) if cobro[5] else None,
                        'mes_pagado': cobro[6],
                        'concepto': cobro[7],
                        'metodo_pago': cobro[8],
                        'estado': cobro[9],
                        'es_cobro_previsto': cobro[10] if len(cobro) > 10 else False,
                        'observaciones': cobro[11] if tiene_observaciones and len(cobro) > 11 else None,
                        'fecha_creacion': cobro[idx_fecha_creacion].isoformat() if len(cobro) > idx_fecha_creacion and cobro[idx_fecha_creacion] else None,
                        'tipo': 'mensual'
                    })
                except (IndexError, TypeError, AttributeError) as e:
                    app.logger.error(f"Error al formatear cobro mensual: {str(e)}, tupla len: {len(cobro) if cobro else 0}")
                    continue
            
            for cobro in ultimos_extras:
                try:
                    resultado.append({
                        'id_pago': cobro[0],
                        'id_residente': cobro[1],
                        'residente': cobro[2],
                        'monto': float(cobro[3]) if cobro[3] is not None else 0.0,
                        'fecha_pago': str(cobro[4]) if cobro[4] else None,
                        'fecha_prevista': str(cobro[5]) if cobro[5] else None,
                        'mes_pagado': cobro[6],
                        'concepto': cobro[7],
                        'metodo_pago': cobro[8],
                        'estado': cobro[9],
                        'es_cobro_previsto': cobro[10] if len(cobro) > 10 else False,
                        'observaciones': cobro[11] if tiene_observaciones and len(cobro) > 11 else None,
                        'fecha_creacion': cobro[idx_fecha_creacion].isoformat() if len(cobro) > idx_fecha_creacion and cobro[idx_fecha_creacion] else None,
                        'tipo': 'extra'
                    })
                except (IndexError, TypeError, AttributeError) as e:
                    app.logger.error(f"Error al formatear cobro extra: {str(e)}, tupla: {cobro}, len: {len(cobro) if cobro else 0}")
                    continue
            
            return jsonify({'cobros': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        import traceback
        app.logger.error(f"Error al obtener últimos cobros completados: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'error': f'Error al obtener últimos cobros completados: {str(e)}'}), 500


@app.route('/api/v1/facturacion/cobros/<int:id_pago>', methods=['GET'])
def obtener_cobro(id_pago):
    """Obtiene un cobro específico por su ID."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Primero verificar que el cobro existe y pertenece a la residencia
            cursor.execute("""
                SELECT id_pago, id_residente, id_residencia
                FROM pago_residente
                WHERE id_pago = %s
            """, (id_pago,))
            
            cobro_basico = cursor.fetchone()
            
            if not cobro_basico:
                app.logger.warning(f"Cobro {id_pago} no encontrado")
                return jsonify({'error': 'Cobro no encontrado'}), 404
            
            # Verificar que el usuario tiene acceso a la residencia del cobro
            is_valid, error_response = validate_residencia_access(cobro_basico[2])
            if not is_valid:
                return error_response
            
            # Ahora obtener la información completa con JOIN
            cursor.execute("""
                SELECT p.id_pago, p.id_residente, p.id_residencia,
                       COALESCE(r.nombre || ' ' || r.apellido, 'Residente no encontrado') as residente,
                       p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                       p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion
                FROM pago_residente p
                LEFT JOIN residente r ON p.id_residente = r.id_residente
                WHERE p.id_pago = %s
            """, (id_pago,))
            
            cobro = cursor.fetchone()
            
            if not cobro:
                return jsonify({'error': 'Error al obtener información del cobro'}), 500
            
            resultado = {
                'id_pago': cobro[0],
                'id_residente': cobro[1],
                'id_residencia': cobro[2],
                'residente': cobro[3],  # COALESCE(r.nombre || ' ' || r.apellido, ...)
                'monto': float(cobro[4]),  # p.monto
                'fecha_pago': str(cobro[5]) if cobro[5] else None,  # p.fecha_pago
                'fecha_prevista': str(cobro[6]) if cobro[6] else None,  # p.fecha_prevista
                'mes_pagado': cobro[7],  # p.mes_pagado
                'concepto': cobro[8],  # p.concepto
                'metodo_pago': cobro[9],  # p.metodo_pago
                'estado': cobro[10],  # p.estado
                'es_cobro_previsto': cobro[11],  # p.es_cobro_previsto
                'observaciones': cobro[12],  # p.observaciones
                'fecha_creacion': cobro[13].isoformat() if cobro[13] else None  # p.fecha_creacion
            }
            
            return jsonify(resultado), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al obtener cobro {id_pago}: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Error al obtener cobro', 'details': str(e)}), 500


@app.route('/api/v1/facturacion/cobros/normalizar-conceptos', methods=['POST'])
def normalizar_conceptos_cobros():
    """
    Normaliza los conceptos de cobros existentes:
    - Convierte "Pago mensual habitación" o "Pago [Mes] [Año]" a formato "[Mes] [Año corto]"
    - Ejemplos: "Pago Diciembre 2025" → "Diciembre 25", "Pago mensual habitación" → "Diciembre 25"
    - Basándose en mes_pagado o fecha_prevista
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            meses_espanol = {
                1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril',
                5: 'mayo', 6: 'junio', 7: 'julio', 8: 'agosto',
                9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'
            }
            
            # Obtener cobros con conceptos que necesitan normalización
            # Buscar conceptos que sean "Pago mensual habitación" o "Pago [mes] [año completo]" 
            # y convertirlos a formato "[Mes] [año corto]" (ej: "Diciembre 25")
            cursor.execute("""
                SELECT id_pago, concepto, mes_pagado, fecha_prevista, fecha_pago
                FROM pago_residente
                WHERE concepto ILIKE 'Pago mensual%%' 
                   OR concepto ILIKE 'mensual habitación%%'
                   OR concepto = 'Pago mensual habitación'
                   OR (concepto ILIKE 'Pago %%' AND concepto NOT SIMILAR TO 'Pago (enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre) [0-9]{2}')
                   OR (concepto ILIKE 'Pago %%' AND concepto SIMILAR TO 'Pago (enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre) [0-9]{4}')
            """)
            
            cobros_a_normalizar = cursor.fetchall()
            actualizados = 0
            errores = []
            
            for cobro in cobros_a_normalizar:
                id_pago = cobro[0]
                concepto_actual = cobro[1]
                mes_pagado = cobro[2]
                fecha_prevista = cobro[3]
                fecha_pago = cobro[4]
                
                # Determinar mes y año
                mes = None
                año = None
                
                if mes_pagado:
                    # mes_pagado está en formato 'YYYY-MM'
                    partes = mes_pagado.split('-')
                    if len(partes) == 2:
                        año = int(partes[0])
                        mes = int(partes[1])
                elif fecha_prevista:
                    # fecha_prevista es date
                    if isinstance(fecha_prevista, str):
                        try:
                            fecha = datetime.strptime(fecha_prevista, '%Y-%m-%d')
                            año = fecha.year
                            mes = fecha.month
                        except:
                            pass
                    else:
                        año = fecha_prevista.year
                        mes = fecha_prevista.month
                elif fecha_pago:
                    # fecha_pago es date
                    if isinstance(fecha_pago, str):
                        try:
                            fecha = datetime.strptime(fecha_pago, '%Y-%m-%d')
                            año = fecha.year
                            mes = fecha.month
                        except:
                            pass
                    else:
                        año = fecha_pago.year
                        mes = fecha_pago.month
                
                if mes and año:
                    nombre_mes = meses_espanol.get(mes, 'mes')
                    # Formato: "Diciembre 25", "Enero 26" (solo mes y año corto, sin "Pago")
                    año_corto = str(año)[-2:]  # Últimos 2 dígitos
                    concepto_nuevo = f"{nombre_mes.capitalize()} {año_corto}"
                    
                    try:
                        cursor.execute("""
                            UPDATE pago_residente
                            SET concepto = %s
                            WHERE id_pago = %s
                        """, (concepto_nuevo, id_pago))
                        actualizados += 1
                    except Exception as e:
                        errores.append(f"Error al actualizar cobro {id_pago}: {str(e)}")
                else:
                    errores.append(f"Cobro {id_pago}: No se pudo determinar mes/año")
            
            conn.commit()
            
            return jsonify({
                'mensaje': f'Conceptos normalizados exitosamente',
                'actualizados': actualizados,
                'total_revisados': len(cobros_a_normalizar),
                'errores': errores if errores else None
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al normalizar conceptos: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())
            return jsonify({'error': 'Error al normalizar conceptos', 'details': str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/facturacion/cobros/<int:id_pago>', methods=['PUT'])
def actualizar_cobro(id_pago):
    """Actualiza un cobro (cambiar estado, marcar como cobrado, etc.)."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el cobro existe
            # Verificar que el cobro existe y obtener su residencia
            cursor.execute("""
                SELECT id_pago, id_residencia FROM pago_residente
                WHERE id_pago = %s
            """, (id_pago,))
            
            cobro_existente = cursor.fetchone()
            if not cobro_existente:
                return jsonify({'error': 'Cobro no encontrado'}), 404
            
            # Verificar acceso a la residencia del cobro
            is_valid, error_response = validate_residencia_access(cobro_existente[1])
            if not is_valid:
                return error_response
            
            # Validar datos si se proporcionan
            if 'estado' in data:
                valid, error = validate_estado(data.get('estado'))
                if not valid:
                    return jsonify({'error': error}), 400
            
            if 'monto' in data and data.get('monto') is not None:
                valid, error = validate_monto(data.get('monto'), 'Monto', required=False)
                if not valid:
                    return jsonify({'error': error}), 400
            
            if 'metodo_pago' in data and data.get('metodo_pago'):
                valid, error = validate_metodo_pago(data.get('metodo_pago'), required=False)
                if not valid:
                    return jsonify({'error': error}), 400
            
            # Campos actualizables
            campos_actualizables = [
                'estado', 'fecha_pago', 'fecha_prevista', 'monto', 'concepto',
                'metodo_pago', 'mes_pagado', 'es_cobro_previsto', 'observaciones'
            ]
            
            updates = []
            valores = []
            
            for campo in campos_actualizables:
                if campo in data:
                    updates.append(f"{campo} = %s")
                    valores.append(data[campo])
            
            if not updates:
                return jsonify({'error': 'No hay campos para actualizar'}), 400
            
            # Actualizar el cobro (ya validamos acceso arriba)
            valores.append(id_pago)
            query = f"""
                UPDATE pago_residente
                SET {', '.join(updates)}
                WHERE id_pago = %s
                RETURNING id_pago
            """
            
            cursor.execute(query, valores)
            conn.commit()
            
            return jsonify({'mensaje': 'Cobro actualizado exitosamente'}), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al actualizar cobro: {str(e)}")
            return jsonify({'error': 'Error al actualizar cobro'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/facturacion/cobros/<int:id_pago>', methods=['DELETE'])
def eliminar_cobro(id_pago):
    """Elimina un cobro completamente."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el cobro existe
            cursor.execute("""
                SELECT id_pago, id_residencia FROM pago_residente
                WHERE id_pago = %s
            """, (id_pago,))
            
            cobro = cursor.fetchone()
            
            if not cobro:
                return jsonify({'error': 'Cobro no encontrado'}), 404
            
            # Verificar acceso a la residencia del cobro
            is_valid, error_response = validate_residencia_access(cobro[1])
            if not is_valid:
                return error_response
            
            # Eliminar el cobro
            cursor.execute("""
                DELETE FROM pago_residente
                WHERE id_pago = %s
                RETURNING id_pago
            """, (id_pago,))
            
            eliminado = cursor.fetchone()
            
            if not eliminado:
                return jsonify({'error': 'No se pudo eliminar el cobro'}), 500
            
            conn.commit()
            
            return jsonify({
                'mensaje': 'Cobro eliminado exitosamente',
                'id_pago': id_pago
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al eliminar cobro: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())
            return jsonify({'error': 'Error al eliminar el cobro', 'details': str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/facturacion/proveedores', methods=['GET'])
def listar_pagos_proveedores():
    """Lista los pagos a proveedores de la residencia."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Construir query con filtros por residencias de acceso
            query = """
                SELECT p.id_pago, p.proveedor, p.concepto, p.monto, p.fecha_pago, 
                       p.fecha_prevista, p.metodo_pago, p.estado, p.numero_factura,
                       p.observaciones, p.fecha_creacion, res.id_residencia, res.nombre as nombre_residencia
                FROM pago_proveedor p
                JOIN residencia res ON p.id_residencia = res.id_residencia
                WHERE 1=1
            """
            params = []
            
            # Filtrar por residencias de acceso (excepto super_admin)
            if g.id_rol != SUPER_ADMIN_ROLE_ID:
                if g.residencias_acceso:
                    placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                    query += f" AND p.id_residencia IN ({placeholders})"
                    params.extend(g.residencias_acceso)
                else:
                    # Usuario sin residencias
                    return jsonify({'pagos': [], 'total': 0}), 200
            
            query += " ORDER BY COALESCE(p.fecha_pago, p.fecha_prevista, p.fecha_creacion::date) DESC, p.fecha_creacion DESC"
            
            cursor.execute(query, params)
            pagos = cursor.fetchall()
            
            resultado = []
            for pago in pagos:
                resultado.append({
                    'id_pago': pago[0],
                    'proveedor': pago[1],
                    'concepto': pago[2],
                    'monto': float(pago[3]) if pago[3] else 0,
                    'fecha_pago': str(pago[4]) if pago[4] else None,
                    'fecha_prevista': str(pago[5]) if pago[5] else None,
                    'metodo_pago': pago[6],
                    'estado': pago[7],
                    'numero_factura': pago[8],
                    'observaciones': pago[9],
                    'fecha_creacion': pago[10].isoformat() if pago[10] else None,
                    'id_residencia': pago[11],
                    'nombre_residencia': pago[12]
                })
            
            return jsonify({'pagos': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar pagos a proveedores: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': f'Error al obtener pagos: {str(e)}'}), 500


@app.route('/api/v1/facturacion/proveedores', methods=['POST'])
def crear_pago_proveedor():
    """Crea un pago a proveedor o una estimación basada en historial."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        proveedor = data.get('proveedor')
        concepto = data.get('concepto')
        monto = data.get('monto')
        fecha_pago = data.get('fecha_pago')
        fecha_prevista = data.get('fecha_prevista')
        
        # Validaciones básicas
        valid, error = validate_text(proveedor, 'Proveedor', min_length=2, max_length=255, required=True)
        if not valid:
            return jsonify({'error': error}), 400
        
        valid, error = validate_text(concepto, 'Concepto', min_length=3, max_length=500, required=True)
        if not valid:
            return jsonify({'error': error}), 400
        
        if monto is not None:
            valid, error = validate_monto(monto, 'Monto', required=False)
            if not valid:
                return jsonify({'error': error}), 400
        
        # Calcular estado automáticamente basado en las fechas
        # Si tiene fecha_pago → pagado, si tiene fecha_prevista → pendiente
        if fecha_pago:
            estado = 'pagado'
        elif fecha_prevista:
            estado = 'pendiente'
        else:
            estado = data.get('estado', 'pendiente')  # Por defecto pendiente si no hay fechas
        
        if not monto or monto <= 0:
            return jsonify({'error': 'monto es requerido'}), 400
        
        # Validar que se proporcione id_residencia
        id_residencia = data.get('id_residencia')
        if not id_residencia:
            return jsonify({'error': 'id_residencia es requerido'}), 400
        
        # Verificar acceso a la residencia
        is_valid, error_response = validate_residencia_access(id_residencia)
        if not is_valid:
            return error_response
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO pago_proveedor (id_residencia, proveedor, concepto, monto, fecha_pago,
                                          fecha_prevista, metodo_pago, estado, numero_factura,
                                          observaciones)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_pago
            """, (
                id_residencia,
                proveedor,
                concepto,
                monto,
                fecha_pago,
                fecha_prevista,
                data.get('metodo_pago'),
                estado,  # Calculado automáticamente
                data.get('numero_factura'),
                data.get('observaciones')
            ))
            
            id_pago = cursor.fetchone()[0]
            conn.commit()
            
            return jsonify({
                'id_pago': id_pago,
                'mensaje': 'Pago a proveedor registrado exitosamente'
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear pago a proveedor: {str(e)}")
            return jsonify({'error': 'Error al crear pago a proveedor'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/facturacion/proveedores/<int:id_pago>', methods=['GET'])
def obtener_pago_proveedor(id_pago):
    """Obtiene un pago a proveedor por su ID."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id_pago, id_residencia, proveedor, concepto, monto, fecha_pago, fecha_prevista,
                       metodo_pago, estado, numero_factura, observaciones, fecha_creacion
                FROM pago_proveedor
                WHERE id_pago = %s
            """, (id_pago,))
            
            pago = cursor.fetchone()
            if not pago:
                return jsonify({'error': 'Pago no encontrado'}), 404
            
            # Verificar acceso a la residencia del pago
            is_valid, error_response = validate_residencia_access(pago[1])
            if not is_valid:
                return error_response
            
            # Reconstruir resultado con índices correctos
            pago = (
                pago[0],  # id_pago
                pago[2],  # proveedor
                pago[3],  # concepto
                pago[4],  # monto
                pago[5],  # fecha_pago
                pago[6],  # fecha_prevista
                pago[7],  # metodo_pago
                pago[8],  # estado
                pago[9],  # numero_factura
                pago[10], # observaciones
                pago[11]  # fecha_creacion
            )
            
            pago = cursor.fetchone()
            
            if not pago:
                return jsonify({'error': 'Pago no encontrado'}), 404
            
            return jsonify({
                'id_pago': pago[0],
                'proveedor': pago[1],
                'concepto': pago[2],
                'monto': float(pago[3]),
                'fecha_pago': str(pago[4]) if pago[4] else None,
                'fecha_prevista': str(pago[5]) if pago[5] else None,
                'metodo_pago': pago[6],
                'estado': pago[7],
                'numero_factura': pago[8],
                'observaciones': pago[9],
                'fecha_creacion': pago[10].isoformat() if pago[10] else None
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al obtener pago a proveedor: {str(e)}")
        return jsonify({'error': 'Error al obtener pago a proveedor'}), 500


@app.route('/api/v1/facturacion/proveedores/<int:id_pago>', methods=['PUT'])
def actualizar_pago_proveedor(id_pago):
    """Actualiza un pago a proveedor."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el pago existe y pertenece a la residencia del usuario
            # Verificar que el pago existe y obtener su residencia
            cursor.execute("""
                SELECT id_pago, id_residencia FROM pago_proveedor
                WHERE id_pago = %s
            """, (id_pago,))
            
            pago_existente = cursor.fetchone()
            if not pago_existente:
                return jsonify({'error': 'Pago no encontrado'}), 404
            
            # Verificar acceso a la residencia del pago
            is_valid, error_response = validate_residencia_access(pago_existente[1])
            if not is_valid:
                return error_response
            
            # Preparar datos para actualizar
            updates = []
            valores = []
            
            if 'proveedor' in data:
                updates.append('proveedor = %s')
                valores.append(data['proveedor'])
            
            if 'concepto' in data:
                updates.append('concepto = %s')
                valores.append(data['concepto'])
            
            if 'monto' in data:
                updates.append('monto = %s')
                valores.append(data['monto'])
            
            if 'fecha_pago' in data:
                updates.append('fecha_pago = %s')
                valores.append(data['fecha_pago'] if data['fecha_pago'] else None)
            
            if 'fecha_prevista' in data:
                updates.append('fecha_prevista = %s')
                valores.append(data['fecha_prevista'] if data['fecha_prevista'] else None)
            
            if 'metodo_pago' in data:
                updates.append('metodo_pago = %s')
                valores.append(data['metodo_pago'])
            
            if 'numero_factura' in data:
                updates.append('numero_factura = %s')
                valores.append(data['numero_factura'])
            
            if 'observaciones' in data:
                updates.append('observaciones = %s')
                valores.append(data['observaciones'])
            
            # Calcular estado automáticamente basado en las fechas
            if 'fecha_pago' in data or 'fecha_prevista' in data:
                fecha_pago = data.get('fecha_pago')
                fecha_prevista = data.get('fecha_prevista')
                
                if fecha_pago:
                    estado = 'pagado'
                elif fecha_prevista:
                    estado = 'pendiente'
                else:
                    estado = data.get('estado', 'pendiente')
                
                updates.append('estado = %s')
                valores.append(estado)
            elif 'estado' in data:
                updates.append('estado = %s')
                valores.append(data['estado'])
            
            if not updates:
                return jsonify({'error': 'No hay datos para actualizar'}), 400
            
            valores.append(id_pago)
            
            query = f"""
                UPDATE pago_proveedor
                SET {', '.join(updates)}
                WHERE id_pago = %s
                RETURNING id_pago
            """
            
            cursor.execute(query, valores)
            conn.commit()
            
            return jsonify({
                'mensaje': 'Pago a proveedor actualizado exitosamente',
                'id_pago': id_pago
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al actualizar pago a proveedor: {str(e)}")
            return jsonify({'error': 'Error al actualizar pago a proveedor'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# ============================================================================
# ENDPOINTS DE PROVEEDORES
# ============================================================================

@app.route('/api/v1/proveedores', methods=['GET'])
@permiso_requerido('leer:proveedor')
def listar_proveedores():
    """Lista los proveedores de las residencias del usuario."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Construir filtro de residencias
            where_clause, params = build_residencia_filter('', 'id_residencia')
            
            if where_clause:
                # Usuario normal: filtrar por residencias asignadas
                query = f"""
                    SELECT id_proveedor, id_residencia, nombre, nif_cif, direccion, telefono, email,
                           contacto, tipo_servicio, activo, observaciones, fecha_creacion
                    FROM proveedor
                    {where_clause}
                    ORDER BY nombre
                """
                cursor.execute(query, params)
            else:
                # Super admin: sin filtro (acceso total)
                cursor.execute("""
                    SELECT id_proveedor, id_residencia, nombre, nif_cif, direccion, telefono, email,
                           contacto, tipo_servicio, activo, observaciones, fecha_creacion
                    FROM proveedor
                    ORDER BY nombre
                """)
            
            proveedores = cursor.fetchall()
            
            resultado = []
            for prov in proveedores:
                resultado.append({
                    'id_proveedor': prov[0],
                    'id_residencia': prov[1],
                    'nombre': prov[2],
                    'nif_cif': prov[3],
                    'direccion': prov[4],
                    'telefono': prov[5],
                    'email': prov[6],
                    'contacto': prov[7],
                    'tipo_servicio': prov[8],
                    'activo': prov[9],
                    'observaciones': prov[10],
                    'fecha_creacion': prov[11].isoformat() if prov[11] else None
                })
            
            return jsonify({'proveedores': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar proveedores: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Error al obtener proveedores', 'details': str(e)}), 500


@app.route('/api/v1/proveedores', methods=['POST'])
@permiso_requerido('escribir:proveedor')
def crear_proveedor():
    """Crea un nuevo proveedor."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        nombre = data.get('nombre')
        valid, error = validate_text(nombre, 'Nombre del proveedor', min_length=2, max_length=255, required=True)
        if not valid:
            return jsonify({'error': error}), 400
        
        # Validar email si se proporciona
        if 'email' in data and data.get('email'):
            valid, error = validate_email(data.get('email'))
            if not valid:
                return jsonify({'error': error}), 400
        
        # Validar teléfono si se proporciona
        if 'telefono' in data and data.get('telefono'):
            valid, error = validate_phone(data.get('telefono'), 'Teléfono', required=False)
            if not valid:
                return jsonify({'error': error}), 400
        
        # Obtener id_residencia del request o usar la primera residencia asignada
        id_residencia = data.get('id_residencia')
        
        # Convertir a int si es string
        if id_residencia:
            try:
                id_residencia = int(id_residencia)
            except (ValueError, TypeError):
                return jsonify({'error': 'id_residencia debe ser un número válido'}), 400
        
        # Si no se proporciona id_residencia, usar la primera residencia asignada (si solo hay una)
        if not id_residencia:
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                return jsonify({'error': 'id_residencia es requerido para super_admin'}), 400
            elif not g.residencias_acceso or len(g.residencias_acceso) == 0:
                return jsonify({'error': 'Usuario sin residencias asignadas'}), 403
            elif len(g.residencias_acceso) == 1:
                id_residencia = g.residencias_acceso[0]
            else:
                return jsonify({'error': 'id_residencia es requerido cuando el usuario tiene acceso a múltiples residencias'}), 400
        
        # Validar que el usuario tiene acceso a la residencia especificada
        if g.id_rol != SUPER_ADMIN_ROLE_ID:
            if id_residencia not in g.residencias_acceso:
                return jsonify({'error': 'No tienes permisos para crear proveedores en esta residencia'}), 403
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO proveedor (id_residencia, nombre, nif_cif, direccion, telefono,
                                     email, contacto, tipo_servicio, activo, observaciones)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_proveedor
            """, (
                id_residencia,
                nombre,
                data.get('nif_cif'),
                data.get('direccion'),
                data.get('telefono'),
                data.get('email'),
                data.get('contacto'),
                data.get('tipo_servicio'),
                data.get('activo', True),
                data.get('observaciones')
            ))
            
            id_proveedor = cursor.fetchone()[0]
            conn.commit()
            
            return jsonify({
                'id_proveedor': id_proveedor,
                'mensaje': 'Proveedor creado exitosamente'
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear proveedor: {str(e)}")
            return jsonify({'error': 'Error al crear proveedor'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/proveedores/<int:id_proveedor>', methods=['GET'])
def obtener_proveedor(id_proveedor):
    """Obtiene un proveedor por su ID."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id_proveedor, id_residencia, nombre, nif_cif, direccion, telefono, email,
                       contacto, tipo_servicio, activo, observaciones, fecha_creacion
                FROM proveedor
                WHERE id_proveedor = %s
            """, (id_proveedor,))
            
            prov = cursor.fetchone()
            
            if not prov:
                return jsonify({'error': 'Proveedor no encontrado'}), 404
            
            # Verificar acceso a la residencia del proveedor
            is_valid, error_response = validate_residencia_access(prov[1])
            if not is_valid:
                return error_response
            
            # Reconstruir resultado con índices correctos (omitir id_residencia en la respuesta)
            prov = (
                prov[0],  # id_proveedor
                prov[2],  # nombre
                prov[3],  # nif_cif
                prov[4],  # direccion
                prov[5],  # telefono
                prov[6],  # email
                prov[7],  # contacto
                prov[8],  # tipo_servicio
                prov[9],  # activo
                prov[10], # observaciones
                prov[11]  # fecha_creacion
            )
            
            return jsonify({
                'id_proveedor': prov[0],
                'nombre': prov[1],
                'nif_cif': prov[2],
                'direccion': prov[3],
                'telefono': prov[4],
                'email': prov[5],
                'contacto': prov[6],
                'tipo_servicio': prov[7],
                'activo': prov[8],
                'observaciones': prov[9],
                'fecha_creacion': prov[10].isoformat() if prov[10] else None
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al obtener proveedor: {str(e)}")
        return jsonify({'error': 'Error al obtener proveedor'}), 500


@app.route('/api/v1/proveedores/<int:id_proveedor>/baja', methods=['POST'])
def dar_baja_proveedor(id_proveedor):
    """Da de baja a un proveedor con motivo y fecha."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        motivo_baja = data.get('motivo_baja')
        if not motivo_baja:
            return jsonify({'error': 'El motivo de baja es requerido'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el proveedor existe, está activo y pertenece a la residencia del usuario
            cursor.execute("""
                SELECT id_proveedor, activo, id_residencia FROM proveedor
                WHERE id_proveedor = %s
            """, (id_proveedor,))
            
            proveedor = cursor.fetchone()
            if not proveedor:
                return jsonify({'error': 'Proveedor no encontrado'}), 404
            
            # Verificar que el usuario tiene acceso a la residencia del proveedor
            is_valid, error_response = validate_residencia_access(proveedor[2])
            if not is_valid:
                return error_response
            
            if not proveedor[1]:  # Si ya está inactivo
                return jsonify({'error': 'El proveedor ya está dado de baja'}), 400
            
            # Verificar si las columnas de baja existen
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'proveedor' 
                  AND column_name IN ('motivo_baja', 'fecha_baja')
            """)
            columnas_baja = {row[0] for row in cursor.fetchall()}
            
            # Actualizar el proveedor: activo = False, motivo_baja, fecha_baja = hoy
            from datetime import date
            fecha_baja = date.today()
            
            # Construir la consulta dinámicamente según las columnas que existan
            updates = ['activo = FALSE']
            valores = []
            
            if 'motivo_baja' in columnas_baja:
                updates.append('motivo_baja = %s')
                valores.append(motivo_baja)
            
            if 'fecha_baja' in columnas_baja:
                updates.append('fecha_baja = %s')
                valores.append(fecha_baja)
            
            valores.append(id_proveedor)
            
            query = f"""
                UPDATE proveedor
                SET {', '.join(updates)}
                WHERE id_proveedor = %s
                RETURNING id_proveedor
            """
            
            cursor.execute(query, tuple(valores))
            conn.commit()
            
            return jsonify({
                'mensaje': 'Proveedor dado de baja exitosamente',
                'id_proveedor': id_proveedor,
                'motivo_baja': motivo_baja if 'motivo_baja' in columnas_baja else None,
                'fecha_baja': str(fecha_baja) if 'fecha_baja' in columnas_baja else None
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al dar de baja al proveedor: {str(e)}")
            return jsonify({'error': 'Error al dar de baja al proveedor'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/proveedores/<int:id_proveedor>', methods=['PUT'])
def actualizar_proveedor(id_proveedor):
    """Actualiza un proveedor."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el proveedor existe y obtener su residencia
            cursor.execute("""
                SELECT id_proveedor, id_residencia FROM proveedor
                WHERE id_proveedor = %s
            """, (id_proveedor,))
            
            proveedor_existente = cursor.fetchone()
            if not proveedor_existente:
                return jsonify({'error': 'Proveedor no encontrado'}), 404
            
            # Verificar acceso a la residencia del proveedor
            is_valid, error_response = validate_residencia_access(proveedor_existente[1])
            if not is_valid:
                return error_response
            
            # Campos actualizables
            campos_actualizables = [
                'nombre', 'nif_cif', 'direccion', 'telefono', 'email',
                'contacto', 'tipo_servicio', 'activo', 'observaciones'
            ]
            
            updates = []
            valores = []
            
            for campo in campos_actualizables:
                if campo in data:
                    updates.append(f"{campo} = %s")
                    valores.append(data[campo])
            
            if not updates:
                return jsonify({'error': 'No hay campos para actualizar'}), 400
            
            valores.append(id_proveedor)
            
            query = f"""
                UPDATE proveedor
                SET {', '.join(updates)}
                WHERE id_proveedor = %s
                RETURNING id_proveedor
            """
            
            cursor.execute(query, valores)
            conn.commit()
            
            return jsonify({'mensaje': 'Proveedor actualizado exitosamente'}), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al actualizar proveedor: {str(e)}")
            return jsonify({'error': 'Error al actualizar proveedor'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# ============================================================================
# ENDPOINTS DE PERSONAL
# ============================================================================

@app.route('/api/v1/personal', methods=['GET'])
def listar_personal():
    """Lista el personal de la residencia del usuario."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Construir query según acceso del usuario
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                cursor.execute("""
                    SELECT id_personal, id_residencia, nombre, apellido, documento_identidad,
                           telefono, email, cargo, activo, fecha_contratacion, fecha_creacion
                    FROM personal
                    ORDER BY apellido, nombre
                """)
            else:
                if not g.residencias_acceso:
                    return jsonify({'personal': [], 'total': 0}), 200
                
                placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                cursor.execute(f"""
                    SELECT id_personal, id_residencia, nombre, apellido, documento_identidad,
                           telefono, email, cargo, activo, fecha_contratacion, fecha_creacion
                    FROM personal
                    WHERE id_residencia IN ({placeholders})
                    ORDER BY apellido, nombre
                """, tuple(g.residencias_acceso))
            
            personal_list = cursor.fetchall()
            
            resultado = []
            for p in personal_list:
                resultado.append({
                    'id_personal': p[0],
                    'id_residencia': p[1],
                    'nombre': p[2],
                    'apellido': p[3],
                    'documento_identidad': p[4],
                    'telefono': p[5],
                    'email': p[6],
                    'cargo': p[7],
                    'activo': p[8],
                    'fecha_contratacion': str(p[9]) if p[9] else None,
                    'fecha_creacion': p[10].isoformat() if p[10] else None
                })
            
            return jsonify({'personal': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar personal: {str(e)}")
        return jsonify({'error': 'Error al obtener personal'}), 500


@app.route('/api/v1/personal', methods=['POST'])
def crear_personal():
    """
    Crea un nuevo empleado/personal. Permite elegir la residencia (Violetas 1 o Violetas 2).
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        # Validar datos con el módulo de validación
        is_valid, errors = validate_personal_data(data, is_update=False)
        if not is_valid:
            return jsonify({'error': 'Errores de validación', 'detalles': errors}), 400
        
        nombre = data.get('nombre')
        apellido = data.get('apellido')
        id_residencia = data.get('id_residencia')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que la residencia existe
            cursor.execute("SELECT id_residencia FROM residencia WHERE id_residencia = %s", (id_residencia,))
            if not cursor.fetchone():
                return jsonify({'error': 'Residencia no encontrada'}), 404
            
            cursor.execute("""
                INSERT INTO personal (id_residencia, nombre, apellido, documento_identidad,
                                   telefono, email, cargo, activo, fecha_contratacion)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_personal, fecha_creacion
            """, (
                id_residencia,
                nombre,
                apellido,
                data.get('documento_identidad'),
                data.get('telefono'),
                data.get('email'),
                data.get('cargo'),
                data.get('activo', True),
                data.get('fecha_contratacion')
            ))
            
            resultado = cursor.fetchone()
            id_personal = resultado[0]
            conn.commit()
            
            return jsonify({
                'id_personal': id_personal,
                'mensaje': 'Personal creado exitosamente'
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear personal: {str(e)}")
            return jsonify({'error': 'Error al crear personal'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# ============================================================================
# ENDPOINTS DE TURNOS EXTRA
# ============================================================================

@app.route('/api/v1/turnos-extra', methods=['GET'])
def listar_turnos_extra():
    """Lista los turnos extra de la residencia del usuario."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Obtener parámetros de filtro opcionales
            id_personal = request.args.get('id_personal', type=int)
            aprobado = request.args.get('aprobado', type=str)  # 'true', 'false', o None para todos
            
            # Construir query según acceso del usuario
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                query = """
                    SELECT te.id_turno_extra, te.id_personal, te.id_residencia,
                           te.fecha, te.hora_entrada, te.hora_salida, te.motivo,
                           te.aprobado, te.fecha_creacion,
                           p.nombre || ' ' || p.apellido as nombre_personal,
                           p.cargo
                    FROM turno_extra te
                    JOIN personal p ON te.id_personal = p.id_personal
                    WHERE 1=1
                """
                params = []
            else:
                if not g.residencias_acceso:
                    return jsonify({'turnos_extra': [], 'total': 0}), 200
                
                placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                query = f"""
                    SELECT te.id_turno_extra, te.id_personal, te.id_residencia,
                           te.fecha, te.hora_entrada, te.hora_salida, te.motivo,
                           te.aprobado, te.fecha_creacion,
                           p.nombre || ' ' || p.apellido as nombre_personal,
                           p.cargo
                    FROM turno_extra te
                    JOIN personal p ON te.id_personal = p.id_personal
                    WHERE te.id_residencia IN ({placeholders})
                """
                params = list(g.residencias_acceso)
            
            if id_personal:
                query += " AND te.id_personal = %s"
                params.append(id_personal)
            
            if aprobado is not None:
                if aprobado.lower() == 'true':
                    query += " AND te.aprobado = TRUE"
                elif aprobado.lower() == 'false':
                    query += " AND te.aprobado = FALSE"
            
            query += " ORDER BY te.fecha DESC, te.hora_entrada DESC"
            
            cursor.execute(query, params)
            turnos = cursor.fetchall()
            
            resultado = []
            for t in turnos:
                resultado.append({
                    'id_turno_extra': t[0],
                    'id_personal': t[1],
                    'id_residencia': t[2],
                    'fecha': str(t[3]) if t[3] else None,
                    'hora_entrada': str(t[4]) if t[4] else None,
                    'hora_salida': str(t[5]) if t[5] else None,
                    'motivo': t[6],
                    'aprobado': t[7],
                    'fecha_creacion': t[8].isoformat() if t[8] else None,
                    'nombre_personal': t[9],
                    'cargo': t[10]
                })
            
            return jsonify({'turnos_extra': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar turnos extra: {str(e)}")
        return jsonify({'error': 'Error al obtener turnos extra'}), 500


@app.route('/api/v1/turnos-extra', methods=['POST'])
def crear_turno_extra():
    """Crea un nuevo turno extra."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        # Validar datos
        is_valid, errors = validate_turno_extra_data(data, is_update=False)
        if not is_valid:
            return jsonify({'error': 'Errores de validación', 'detalles': errors}), 400
        
        id_personal = data.get('id_personal')
        fecha = data.get('fecha')
        hora_entrada = data.get('hora_entrada')
        hora_salida = data.get('hora_salida')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el personal existe y obtener su residencia
            cursor.execute("""
                SELECT id_personal, id_residencia FROM personal
                WHERE id_personal = %s
            """, (id_personal,))
            
            personal = cursor.fetchone()
            if not personal:
                return jsonify({'error': 'Personal no encontrado'}), 404
            
            personal_id_residencia = personal[1]
            
            # Verificar acceso a la residencia del personal
            is_valid, error_response = validate_residencia_access(personal_id_residencia)
            if not is_valid:
                return error_response
            
            # Obtener id_residencia del request o usar la del personal
            id_residencia = data.get('id_residencia', personal_id_residencia)
            
            # Verificar que la residencia solicitada esté en la lista de acceso
            if g.id_rol != SUPER_ADMIN_ROLE_ID and id_residencia not in g.residencias_acceso:
                return jsonify({'error': 'No tienes permisos para crear turnos en esta residencia'}), 403
            
            cursor.execute("""
                INSERT INTO turno_extra (id_personal, id_residencia, fecha, hora_entrada, hora_salida, motivo, aprobado)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id_turno_extra, fecha_creacion
            """, (
                id_personal,
                id_residencia,
                fecha,
                hora_entrada,
                hora_salida,
                data.get('motivo'),
                data.get('aprobado', False)
            ))
            
            resultado = cursor.fetchone()
            id_turno_extra = resultado[0]
            conn.commit()
            
            return jsonify({
                'id_turno_extra': id_turno_extra,
                'mensaje': 'Turno extra creado exitosamente'
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear turno extra: {str(e)}")
            return jsonify({'error': 'Error al crear turno extra'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/turnos-extra/<int:id_turno_extra>', methods=['PUT'])
def actualizar_turno_extra(id_turno_extra):
    """Actualiza un turno extra (puede ser para aprobar/rechazar o editar)."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el turno existe y obtener su residencia
            cursor.execute("""
                SELECT id_turno_extra, id_residencia FROM turno_extra
                WHERE id_turno_extra = %s
            """, (id_turno_extra,))
            
            turno = cursor.fetchone()
            if not turno:
                return jsonify({'error': 'Turno extra no encontrado'}), 404
            
            # Verificar acceso a la residencia del turno
            is_valid, error_response = validate_residencia_access(turno[1])
            if not is_valid:
                return error_response
            
            # Construir la consulta de actualización dinámicamente
            updates = []
            params = []
            
            if 'fecha' in data:
                updates.append('fecha = %s')
                params.append(data.get('fecha'))
            
            if 'hora_entrada' in data:
                updates.append('hora_entrada = %s')
                params.append(data.get('hora_entrada'))
            
            if 'hora_salida' in data:
                updates.append('hora_salida = %s')
                params.append(data.get('hora_salida'))
            
            if 'motivo' in data:
                updates.append('motivo = %s')
                params.append(data.get('motivo'))
            
            if 'aprobado' in data:
                updates.append('aprobado = %s')
                params.append(data.get('aprobado'))
            
            if not updates:
                return jsonify({'error': 'No hay campos para actualizar'}), 400
            
            # Validar datos si se están actualizando campos críticos
            if 'fecha' in data or 'hora_entrada' in data or 'hora_salida' in data:
                is_valid, errors = validate_turno_extra_data(data, is_update=True)
                if not is_valid:
                    return jsonify({'error': 'Errores de validación', 'detalles': errors}), 400
            
            params.append(id_turno_extra)
            
            query = f"""
                UPDATE turno_extra
                SET {', '.join(updates)}
                WHERE id_turno_extra = %s
                RETURNING id_turno_extra
            """
            
            cursor.execute(query, params)
            
            if not cursor.fetchone():
                return jsonify({'error': 'Error al actualizar turno extra'}), 500
            
            conn.commit()
            
            return jsonify({
                'mensaje': 'Turno extra actualizado exitosamente'
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al actualizar turno extra: {str(e)}")
            return jsonify({'error': 'Error al actualizar turno extra'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/turnos-extra/<int:id_turno_extra>', methods=['DELETE'])
def eliminar_turno_extra(id_turno_extra):
    """Elimina un turno extra."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el turno existe y obtener su residencia
            cursor.execute("""
                SELECT id_turno_extra, id_residencia FROM turno_extra
                WHERE id_turno_extra = %s
            """, (id_turno_extra,))
            
            turno = cursor.fetchone()
            if not turno:
                return jsonify({'error': 'Turno extra no encontrado'}), 404
            
            # Verificar acceso a la residencia del turno
            is_valid, error_response = validate_residencia_access(turno[1])
            if not is_valid:
                return error_response
            
            cursor.execute("""
                DELETE FROM turno_extra
                WHERE id_turno_extra = %s
                RETURNING id_turno_extra
            """, (id_turno_extra,))
            
            conn.commit()
            
            return jsonify({
                'mensaje': 'Turno extra eliminado exitosamente'
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al eliminar turno extra: {str(e)}")
            return jsonify({'error': 'Error al eliminar turno extra'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# ============================================================================
# ENDPOINTS DE DOCUMENTACIÓN DE RESIDENTES
# ============================================================================

@app.route('/api/v1/residentes/<int:id_residente>/documentos', methods=['GET'])
def listar_documentos_residente(id_residente):
    """Lista los documentos de un residente. Permite ver documentos de residentes de cualquier residencia."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el residente existe (sin filtrar por residencia del usuario)
            cursor.execute("""
                SELECT id_residente, id_residencia FROM residente 
                WHERE id_residente = %s
            """, (id_residente,))
            
            residente = cursor.fetchone()
            if not residente:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            # Obtener la residencia real del residente
            id_residencia_residente = residente[1]
            
            cursor.execute("""
                SELECT id_documento, tipo_documento, nombre_archivo, descripcion,
                       fecha_subida, fecha_creacion, url_archivo, tamaño_bytes, tipo_mime
                FROM documento_residente
                WHERE id_residente = %s AND id_residencia = %s
                ORDER BY fecha_subida DESC
            """, (id_residente, id_residencia_residente))
            
            documentos = cursor.fetchall()
            
            resultado = []
            for doc in documentos:
                url_descarga = None
                if doc[6]:  # Si hay url_archivo
                    url_descarga = get_document_url(doc[6], expiration_minutes=60)
                
                resultado.append({
                    'id_documento': doc[0],
                    'tipo_documento': doc[1],
                    'nombre_archivo': doc[2],
                    'descripcion': doc[3],
                    'fecha_subida': doc[4].isoformat() if doc[4] else None,
                    'fecha_creacion': doc[5].isoformat() if doc[5] else None,
                    'url_archivo': doc[6],
                    'url_descarga': url_descarga,
                    'tamaño_bytes': doc[7],
                    'tipo_mime': doc[8]
                })
            
            return jsonify({'documentos': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar documentos: {str(e)}")
        return jsonify({'error': 'Error al obtener documentos'}), 500


@app.route('/api/v1/residentes/<int:id_residente>/documentos', methods=['POST'])
def crear_documento_residente(id_residente):
    """Crea un nuevo documento para un residente y lo sube a Cloud Storage."""
    try:
        # Verificar si hay archivo en la petición
        if 'archivo' not in request.files:
            # Si no hay archivo, crear solo el registro (modo compatible)
            data = request.get_json() if request.is_json else {}
            tipo_documento = data.get('tipo_documento') or request.form.get('tipo_documento')
            nombre_archivo = data.get('nombre_archivo') or request.form.get('nombre_archivo')
            descripcion = data.get('descripcion') or request.form.get('descripcion')
            
            if not tipo_documento or not nombre_archivo:
                return jsonify({'error': 'tipo_documento y nombre_archivo son requeridos'}), 400
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            try:
                # Verificar que el residente existe (sin filtrar por residencia del usuario)
                cursor.execute("""
                    SELECT id_residente, id_residencia FROM residente 
                    WHERE id_residente = %s
                """, (id_residente,))
                
                residente = cursor.fetchone()
                if not residente:
                    return jsonify({'error': 'Residente no encontrado'}), 404
                
                id_residencia = residente[1]
                
                cursor.execute("""
                    INSERT INTO documento_residente (id_residente, id_residencia, tipo_documento,
                                                    nombre_archivo, descripcion)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id_documento, fecha_subida
                """, (id_residente, id_residencia, tipo_documento, nombre_archivo, descripcion))
                
                resultado = cursor.fetchone()
                id_documento = resultado[0]
                conn.commit()
                
                return jsonify({
                    'id_documento': id_documento,
                    'mensaje': 'Documento creado exitosamente'
                }), 201
                
            except Exception as e:
                conn.rollback()
                app.logger.error(f"Error al crear documento: {str(e)}")
                return jsonify({'error': 'Error al crear documento'}), 500
            finally:
                cursor.close()
                conn.close()
        
        # Si hay archivo, subirlo a Cloud Storage
        archivo = request.files['archivo']
        tipo_documento = request.form.get('tipo_documento')
        descripcion = request.form.get('descripcion')
        
        if not tipo_documento:
            return jsonify({'error': 'tipo_documento es requerido'}), 400
        
        if archivo.filename == '':
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el residente existe (sin filtrar por residencia del usuario)
            cursor.execute("""
                SELECT id_residente, id_residencia FROM residente 
                WHERE id_residente = %s
            """, (id_residente,))
            
            residente = cursor.fetchone()
            if not residente:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            id_residencia = residente[1]
            
            # Leer contenido del archivo
            file_content = archivo.read()
            nombre_archivo = secure_filename(archivo.filename)
            tipo_mime = archivo.content_type or mimetypes.guess_type(nombre_archivo)[0] or 'application/octet-stream'
            tamaño_bytes = len(file_content)
            
            # Subir a Cloud Storage
            try:
                blob_path = upload_document(
                    file_content=file_content,
                    id_residencia=id_residencia,
                    id_residente=id_residente,
                    tipo_documento=tipo_documento,
                    nombre_archivo=nombre_archivo,
                    content_type=tipo_mime
                )
                
                if not blob_path:
                    app.logger.error("upload_document retornó None")
                    return jsonify({
                        'error': 'Error al subir el archivo a Cloud Storage. Verifique la configuración de GOOGLE_APPLICATION_CREDENTIALS y GCS_BUCKET_NAME'
                    }), 500
            except Exception as upload_error:
                app.logger.error(f"Error al subir documento a Cloud Storage: {str(upload_error)}")
                return jsonify({
                    'error': f'Error al subir el archivo: {str(upload_error)}'
                }), 500
            
            # Guardar en base de datos
            cursor.execute("""
                INSERT INTO documento_residente (id_residente, id_residencia, tipo_documento,
                                                nombre_archivo, descripcion, url_archivo,
                                                tamaño_bytes, tipo_mime)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_documento, fecha_subida
            """, (
                id_residente,
                id_residencia,
                tipo_documento,
                nombre_archivo,
                descripcion,
                blob_path,
                tamaño_bytes,
                tipo_mime
            ))
            
            resultado = cursor.fetchone()
            id_documento = resultado[0]
            conn.commit()
            
            return jsonify({
                'id_documento': id_documento,
                'mensaje': 'Documento subido exitosamente',
                'url_archivo': blob_path
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear documento: {str(e)}", exc_info=True)
            return jsonify({'error': f'Error al crear documento: {str(e)}'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/documentos/<int:id_documento>', methods=['DELETE'])
def eliminar_documento(id_documento):
    """Elimina un documento de la base de datos y de Cloud Storage."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Obtener información del documento incluyendo url_archivo (sin filtrar por residencia del usuario)
            cursor.execute("""
                SELECT id_documento, url_archivo FROM documento_residente 
                WHERE id_documento = %s
            """, (id_documento,))
            
            documento = cursor.fetchone()
            if not documento:
                return jsonify({'error': 'Documento no encontrado'}), 404
            
            url_archivo = documento[1]
            
            # Eliminar de Cloud Storage si existe
            if url_archivo:
                try:
                    delete_document(url_archivo)
                except Exception as e:
                    app.logger.warning(f"No se pudo eliminar archivo de Cloud Storage: {str(e)}")
            
            # Eliminar de base de datos
            cursor.execute("""
                DELETE FROM documento_residente 
                WHERE id_documento = %s
            """, (id_documento,))
            
            conn.commit()
            
            return jsonify({'mensaje': 'Documento eliminado exitosamente'}), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al eliminar documento: {str(e)}")
            return jsonify({'error': 'Error al eliminar documento'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/documentos/<int:id_documento>/descargar', methods=['GET'])
def descargar_documento(id_documento):
    """Genera una URL firmada para descargar un documento."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el documento existe (sin filtrar por residencia del usuario)
            cursor.execute("""
                SELECT url_archivo FROM documento_residente 
                WHERE id_documento = %s
            """, (id_documento,))
            
            documento = cursor.fetchone()
            if not documento:
                return jsonify({'error': 'Documento no encontrado'}), 404
            
            url_archivo = documento[0]
            
            if not url_archivo:
                return jsonify({'error': 'El documento no tiene archivo asociado'}), 404
            
            # Generar URL firmada válida por 1 hora
            url_descarga = get_document_url(url_archivo, expiration_minutes=60)
            
            if not url_descarga:
                return jsonify({'error': 'Error al generar URL de descarga'}), 500
            
            return jsonify({'url_descarga': url_descarga}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# ============================================================================
# ENDPOINTS DE USUARIOS Y CONFIGURACIÓN
# ============================================================================

@app.route('/api/v1/roles', methods=['GET'])
def listar_roles():
    """Lista todos los roles disponibles."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id_rol, nombre, descripcion, activo
                FROM rol
                WHERE activo = TRUE
                ORDER BY id_rol
            """)
            
            roles = cursor.fetchall()
            
            return jsonify({
                'roles': [
                    {
                        'id_rol': r[0],
                        'nombre': r[1],
                        'descripcion': r[2],
                        'activo': r[3]
                    }
                    for r in roles
                ]
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar roles: {str(e)}")
        return jsonify({'error': 'Error al obtener roles'}), 500


@app.route('/api/v1/residencias', methods=['GET'])
def listar_residencias():
    """Lista todas las residencias disponibles."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Si es superadmin, mostrar todas las residencias (activas e inactivas)
            # Si no es superadmin, solo mostrar activas
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                cursor.execute("""
                    SELECT id_residencia, nombre, direccion, telefono, activa, fecha_creacion
                    FROM residencia
                    ORDER BY id_residencia
                """)
            else:
                cursor.execute("""
                    SELECT id_residencia, nombre, direccion, telefono, activa, fecha_creacion
                    FROM residencia
                    WHERE activa = TRUE
                    ORDER BY id_residencia
                """)
            
            residencias = cursor.fetchall()
            
            return jsonify({
                'residencias': [
                    {
                        'id_residencia': r[0],
                        'nombre': r[1],
                        'direccion': r[2],
                        'telefono': r[3],
                        'activa': r[4],
                        'fecha_creacion': r[5].isoformat() if r[5] else None
                    }
                    for r in residencias
                ],
                'total': len(residencias)
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar residencias: {str(e)}")
        return jsonify({'error': 'Error al obtener residencias'}), 500


@app.route('/api/v1/residencias', methods=['POST'])
@permiso_requerido('escribir:residencia')
def crear_residencia():
    """Crea una nueva residencia. Solo superadmin."""
    # Verificar que es superadmin
    if g.id_rol != SUPER_ADMIN_ROLE_ID:
        return jsonify({'error': 'Solo el super administrador puede crear residencias'}), 403
    
    try:
        data = request.get_json()
        
        # Validar datos requeridos
        if not data or 'nombre' not in data:
            return jsonify({'error': 'El nombre es requerido'}), 400
        
        nombre = data.get('nombre', '').strip()
        direccion = data.get('direccion', '').strip() if data.get('direccion') else None
        telefono = data.get('telefono', '').strip() if data.get('telefono') else None
        activa = data.get('activa', True)
        
        # Validar nombre
        if not nombre or len(nombre) < 2:
            return jsonify({'error': 'El nombre debe tener al menos 2 caracteres'}), 400
        
        if len(nombre) > 255:
            return jsonify({'error': 'El nombre es demasiado largo (máximo 255 caracteres)'}), 400
        
        # Validar teléfono si se proporciona
        if telefono and len(telefono) > 50:
            return jsonify({'error': 'El teléfono es demasiado largo (máximo 50 caracteres)'}), 400
        
        # Validar dirección si se proporciona
        if direccion and len(direccion) > 500:
            return jsonify({'error': 'La dirección es demasiado larga (máximo 500 caracteres)'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que no exista una residencia con el mismo nombre
            cursor.execute("""
                SELECT id_residencia FROM residencia WHERE LOWER(nombre) = LOWER(%s)
            """, (nombre,))
            
            if cursor.fetchone():
                return jsonify({'error': 'Ya existe una residencia con ese nombre'}), 400
            
            # Crear la residencia
            cursor.execute("""
                INSERT INTO residencia (nombre, direccion, telefono, activa)
                VALUES (%s, %s, %s, %s)
                RETURNING id_residencia, nombre, direccion, telefono, activa, fecha_creacion
            """, (nombre, direccion, telefono, activa))
            
            residencia = cursor.fetchone()
            conn.commit()
            
            return jsonify({
                'mensaje': 'Residencia creada exitosamente',
                'residencia': {
                    'id_residencia': residencia[0],
                    'nombre': residencia[1],
                    'direccion': residencia[2],
                    'telefono': residencia[3],
                    'activa': residencia[4],
                    'fecha_creacion': residencia[5].isoformat() if residencia[5] else None
                }
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear residencia: {str(e)}")
            return jsonify({'error': 'Error al crear la residencia'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al crear residencia: {str(e)}")
        return jsonify({'error': 'Error al procesar la solicitud'}), 500


@app.route('/api/v1/residencias/<int:id_residencia>', methods=['PUT'])
@permiso_requerido('escribir:residencia')
def actualizar_residencia(id_residencia):
    """Actualiza una residencia existente. Solo superadmin."""
    # Verificar que es superadmin
    if g.id_rol != SUPER_ADMIN_ROLE_ID:
        return jsonify({'error': 'Solo el super administrador puede actualizar residencias'}), 403
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No se proporcionaron datos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que la residencia existe
            cursor.execute("""
                SELECT id_residencia, nombre FROM residencia WHERE id_residencia = %s
            """, (id_residencia,))
            
            residencia_existente = cursor.fetchone()
            if not residencia_existente:
                return jsonify({'error': 'Residencia no encontrada'}), 404
            
            # Preparar campos a actualizar
            updates = []
            params = []
            
            if 'nombre' in data:
                nombre = data.get('nombre', '').strip()
                if not nombre or len(nombre) < 2:
                    return jsonify({'error': 'El nombre debe tener al menos 2 caracteres'}), 400
                if len(nombre) > 255:
                    return jsonify({'error': 'El nombre es demasiado largo (máximo 255 caracteres)'}), 400
                
                # Verificar que no exista otra residencia con el mismo nombre
                cursor.execute("""
                    SELECT id_residencia FROM residencia 
                    WHERE LOWER(nombre) = LOWER(%s) AND id_residencia != %s
                """, (nombre, id_residencia))
                
                if cursor.fetchone():
                    return jsonify({'error': 'Ya existe otra residencia con ese nombre'}), 400
                
                updates.append("nombre = %s")
                params.append(nombre)
            
            if 'direccion' in data:
                direccion = data.get('direccion', '').strip() if data.get('direccion') else None
                if direccion and len(direccion) > 500:
                    return jsonify({'error': 'La dirección es demasiado larga (máximo 500 caracteres)'}), 400
                updates.append("direccion = %s")
                params.append(direccion)
            
            if 'telefono' in data:
                telefono = data.get('telefono', '').strip() if data.get('telefono') else None
                if telefono and len(telefono) > 50:
                    return jsonify({'error': 'El teléfono es demasiado largo (máximo 50 caracteres)'}), 400
                updates.append("telefono = %s")
                params.append(telefono)
            
            if 'activa' in data:
                activa = bool(data.get('activa'))
                updates.append("activa = %s")
                params.append(activa)
            
            if not updates:
                return jsonify({'error': 'No se proporcionaron campos para actualizar'}), 400
            
            # Ejecutar actualización
            params.append(id_residencia)
            query = f"""
                UPDATE residencia 
                SET {', '.join(updates)}
                WHERE id_residencia = %s
                RETURNING id_residencia, nombre, direccion, telefono, activa, fecha_creacion
            """
            
            cursor.execute(query, params)
            residencia = cursor.fetchone()
            conn.commit()
            
            return jsonify({
                'mensaje': 'Residencia actualizada exitosamente',
                'residencia': {
                    'id_residencia': residencia[0],
                    'nombre': residencia[1],
                    'direccion': residencia[2],
                    'telefono': residencia[3],
                    'activa': residencia[4],
                    'fecha_creacion': residencia[5].isoformat() if residencia[5] else None
                }
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al actualizar residencia: {str(e)}")
            return jsonify({'error': 'Error al actualizar la residencia'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al actualizar residencia: {str(e)}")
        return jsonify({'error': 'Error al procesar la solicitud'}), 500


@app.route('/api/v1/residencias/<int:id_residencia>', methods=['DELETE'])
@permiso_requerido('escribir:residencia')
def eliminar_residencia(id_residencia):
    """Elimina (desactiva) una residencia. Solo superadmin."""
    # Verificar que es superadmin
    if g.id_rol != SUPER_ADMIN_ROLE_ID:
        return jsonify({'error': 'Solo el super administrador puede eliminar residencias'}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que la residencia existe
            cursor.execute("""
                SELECT id_residencia, nombre FROM residencia WHERE id_residencia = %s
            """, (id_residencia,))
            
            residencia = cursor.fetchone()
            if not residencia:
                return jsonify({'error': 'Residencia no encontrada'}), 404
            
            # Verificar si hay residentes activos en esta residencia
            cursor.execute("""
                SELECT COUNT(*) FROM residente 
                WHERE id_residencia = %s AND activo = TRUE
            """, (id_residencia,))
            
            residentes_activos = cursor.fetchone()[0]
            
            # Verificar si hay usuarios asignados a esta residencia
            cursor.execute("""
                SELECT COUNT(*) FROM usuario_residencia 
                WHERE id_residencia = %s
            """, (id_residencia,))
            
            usuarios_asignados = cursor.fetchone()[0]
            
            # En lugar de eliminar físicamente, desactivamos la residencia
            cursor.execute("""
                UPDATE residencia 
                SET activa = FALSE
                WHERE id_residencia = %s
                RETURNING id_residencia, nombre, activa
            """, (id_residencia,))
            
            residencia_actualizada = cursor.fetchone()
            conn.commit()
            
            return jsonify({
                'mensaje': 'Residencia desactivada exitosamente',
                'residencia': {
                    'id_residencia': residencia_actualizada[0],
                    'nombre': residencia_actualizada[1],
                    'activa': residencia_actualizada[2]
                },
                'advertencias': {
                    'residentes_activos': residentes_activos,
                    'usuarios_asignados': usuarios_asignados
                }
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al eliminar residencia: {str(e)}")
            return jsonify({'error': 'Error al eliminar la residencia'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al eliminar residencia: {str(e)}")
        return jsonify({'error': 'Error al procesar la solicitud'}), 500


@app.route('/api/v1/usuarios/me', methods=['GET'])
def obtener_usuario_actual():
    """Obtiene la información del usuario actual."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Consulta que maneja tanto usuarios con id_residencia como super_admin sin id_residencia
            cursor.execute("""
                SELECT u.id_usuario, u.email, u.nombre, u.apellido, u.id_rol, u.id_residencia,
                       r.nombre as nombre_rol, res.nombre as nombre_residencia, u.activo, u.requiere_cambio_clave
                FROM usuario u
                JOIN rol r ON u.id_rol = r.id_rol
                LEFT JOIN residencia res ON u.id_residencia = res.id_residencia
                WHERE u.id_usuario = %s
            """, (g.id_usuario,))
            
            usuario = cursor.fetchone()
            
            if not usuario:
                return jsonify({'error': 'Usuario no encontrado'}), 404
            
            # Si es super_admin, obtener todas las residencias asignadas desde usuario_residencia
            residencias = []
            if g.id_rol == SUPER_ADMIN_ROLE_ID:
                # Super admin: acceso total (sin residencias específicas asignadas)
                residencias = []
                cursor.execute("SELECT id_residencia, nombre FROM residencia WHERE activa = TRUE ORDER BY nombre")
                todas_residencias = cursor.fetchall()
                residencias = [{'id_residencia': r[0], 'nombre': r[1]} for r in todas_residencias]
            else:
                # Usuario normal: obtener residencias asignadas
                cursor.execute("""
                    SELECT ur.id_residencia, res.nombre
                    FROM usuario_residencia ur
                    JOIN residencia res ON ur.id_residencia = res.id_residencia
                    WHERE ur.id_usuario = %s AND res.activa = TRUE
                    ORDER BY res.nombre
                """, (g.id_usuario,))
                residencias_data = cursor.fetchall()
                residencias = [{'id_residencia': r[0], 'nombre': r[1]} for r in residencias_data]
            
            return jsonify({
                'id_usuario': usuario[0],
                'email': usuario[1],
                'nombre': usuario[2],
                'apellido': usuario[3],
                'id_rol': usuario[4],
                'id_residencia': usuario[5],  # Puede ser NULL para super_admin
                'nombre_rol': usuario[6],
                'nombre_residencia': usuario[7] if usuario[7] else None,  # NULL para super_admin
                'activo': usuario[8],
                'requiere_cambio_clave': usuario[9] if len(usuario) > 9 else False,
                'residencias': residencias  # Lista de residencias asignadas
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al obtener usuario actual: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Error al obtener información del usuario'}), 500


@app.route('/api/v1/usuarios', methods=['GET'])
def listar_usuarios():
    """Lista todos los usuarios del sistema (solo administradores)."""
    if g.id_rol != 1:
        return jsonify({'error': 'No tienes permisos para acceder a esta información'}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT u.id_usuario, u.email, u.nombre, u.apellido, u.id_rol, u.id_residencia,
                       r.nombre as nombre_rol, res.nombre as nombre_residencia, u.activo, u.fecha_creacion
                FROM usuario u
                JOIN rol r ON u.id_rol = r.id_rol
                JOIN residencia res ON u.id_residencia = res.id_residencia
                ORDER BY u.fecha_creacion DESC
            """)
            
            usuarios = cursor.fetchall()
            
            return jsonify({
                'usuarios': [
                    {
                        'id_usuario': u[0],
                        'email': u[1],
                        'nombre': u[2],
                        'apellido': u[3],
                        'id_rol': u[4],
                        'id_residencia': u[5],
                        'nombre_rol': u[6],
                        'nombre_residencia': u[7],
                        'activo': u[8],
                        'fecha_creacion': u[9].isoformat() if u[9] else None
                    }
                    for u in usuarios
                ]
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar usuarios: {str(e)}")
        return jsonify({'error': 'Error al obtener usuarios'}), 500


@app.route('/api/v1/usuarios/<int:id_usuario>', methods=['PUT'])
def actualizar_usuario(id_usuario):
    """Actualiza un usuario. Los usuarios pueden actualizar su propia información, los super_admin pueden actualizar cualquiera."""
    # Verificar permisos: solo el propio usuario o un super_admin puede actualizar
    if g.id_rol != SUPER_ADMIN_ROLE_ID and g.id_usuario != id_usuario:
        return jsonify({'error': 'No tienes permisos para actualizar este usuario'}), 403
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el usuario existe
            cursor.execute("SELECT id_usuario, id_rol FROM usuario WHERE id_usuario = %s", (id_usuario,))
            usuario_existente = cursor.fetchone()
            
            if not usuario_existente:
                return jsonify({'error': 'Usuario no encontrado'}), 404
            
            # Si no es super_admin, solo puede actualizar ciertos campos (y solo su propia cuenta)
            if g.id_rol != SUPER_ADMIN_ROLE_ID:
                # Usuario normal solo puede actualizar nombre, apellido y contraseña (solo su propia cuenta)
                updates = []
                params = []
                
                if 'nombre' in data:
                    updates.append("nombre = %s")
                    params.append(data.get('nombre'))
                
                if 'apellido' in data:
                    updates.append("apellido = %s")
                    params.append(data.get('apellido'))
                
                if 'password' in data:
                    password = data.get('password')
                    # Validar fuerza de contraseña
                    is_valid, error_msg = validate_password_strength(password)
                    if not is_valid:
                        return jsonify({'error': error_msg}), 400
                    password_hash = generate_password_hash(password)
                    updates.append("password_hash = %s")
                    updates.append("requiere_cambio_clave = FALSE")  # Marcar que ya cambió la contraseña
                    params.append(password_hash)
                
                if not updates:
                    return jsonify({'error': 'No hay campos para actualizar'}), 400
                
                params.append(id_usuario)
                cursor.execute(f"""
                    UPDATE usuario
                    SET {', '.join(updates)}
                    WHERE id_usuario = %s
                """, params)
                conn.commit()
                
                return jsonify({'mensaje': 'Información actualizada exitosamente'}), 200
                
            else:
                # Admin puede actualizar todos los campos excepto la contraseña (se maneja por separado)
                updates = []
                params = []
                
                if 'email' in data:
                    email = data.get('email')
                    valid, error = validate_email(email)
                    if not valid:
                        return jsonify({'error': error}), 400
                    # Verificar que el email no esté en uso por otro usuario
                    cursor.execute("SELECT id_usuario FROM usuario WHERE email = %s AND id_usuario != %s", (email, id_usuario))
                    if cursor.fetchone():
                        return jsonify({'error': 'El email ya está registrado'}), 400
                    updates.append("email = %s")
                    params.append(email)
                
                if 'nombre' in data:
                    updates.append("nombre = %s")
                    params.append(data.get('nombre'))
                
                if 'apellido' in data:
                    updates.append("apellido = %s")
                    params.append(data.get('apellido'))
                
                if 'id_rol' in data:
                    # Verificar que el rol existe
                    cursor.execute("SELECT id_rol FROM rol WHERE id_rol = %s AND activo = TRUE", (data.get('id_rol'),))
                    if not cursor.fetchone():
                        return jsonify({'error': 'Rol no válido'}), 400
                    updates.append("id_rol = %s")
                    params.append(data.get('id_rol'))
                
                if 'id_residencia' in data:
                    # Verificar que la residencia existe
                    cursor.execute("SELECT id_residencia FROM residencia WHERE id_residencia = %s AND activa = TRUE", (data.get('id_residencia'),))
                    if not cursor.fetchone():
                        return jsonify({'error': 'Residencia no válida'}), 400
                    updates.append("id_residencia = %s")
                    params.append(data.get('id_residencia'))
                
                if 'activo' in data:
                    updates.append("activo = %s")
                    params.append(data.get('activo'))
                
                if 'password' in data:
                    password = data.get('password')
                    # Validar fuerza de contraseña
                    is_valid, error_msg = validate_password_strength(password)
                    if not is_valid:
                        return jsonify({'error': error_msg}), 400
                    password_hash = generate_password_hash(password)
                    updates.append("password_hash = %s")
                    updates.append("requiere_cambio_clave = FALSE")  # Marcar que ya cambió la contraseña
                    params.append(password_hash)
                
                if not updates:
                    return jsonify({'error': 'No hay campos para actualizar'}), 400
                
                params.append(id_usuario)
                cursor.execute(f"""
                    UPDATE usuario
                    SET {', '.join(updates)}
                    WHERE id_usuario = %s
                """, params)
            
            conn.commit()
            
            return jsonify({
                'mensaje': 'Usuario actualizado exitosamente'
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al actualizar usuario: {str(e)}")
            return jsonify({'error': 'Error al actualizar usuario'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.errorhandler(404)
def not_found(error):
    """Manejo de errores 404."""
    return jsonify({'error': 'Endpoint no encontrado'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores 500."""
    return jsonify({'error': 'Error interno del servidor'}), 500


# ============================================================================
# ENDPOINTS DE DOCUMENTACIÓN UNIFICADA
# ============================================================================

@app.route('/api/v1/documentacion', methods=['GET'])
def listar_documentacion():
    """
    Lista todos los documentos con filtros opcionales por tipo de entidad, categoría y residencia.
    
    Query params:
    - tipo_entidad: 'residente', 'proveedor', 'personal' (opcional)
    - categoria: 'medica', 'fiscal', 'sanitaria', 'laboral', 'otra' (opcional)
    - id_residencia: ID de residencia (opcional, se filtra automáticamente por permisos)
    - id_entidad: ID específico de la entidad (opcional)
    """
    try:
        tipo_entidad = request.args.get('tipo_entidad')
        categoria = request.args.get('categoria')
        id_entidad = request.args.get('id_entidad', type=int)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Construir filtro de residencias
            residencias_filtro = ""
            params = []
            
            if g.id_rol != SUPER_ADMIN_ROLE_ID:
                if g.residencias_acceso:
                    placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                    residencias_filtro = f" AND id_residencia IN ({placeholders})"
                    params.extend(g.residencias_acceso)
                else:
                    # Usuario sin residencias
                    return jsonify({'documentos': [], 'total': 0}), 200
            
            # Construir query unificada: documentos unificados + documentos legacy de residentes
            # Primero: documentos de la tabla unificada 'documento'
            query_unificados = f"""
                SELECT d.id_documento, d.tipo_entidad, d.id_entidad, d.id_residencia,
                       d.categoria_documento, d.tipo_documento, d.nombre_archivo, d.descripcion,
                       d.fecha_subida, d.url_archivo, d.tamaño_bytes, d.tipo_mime,
                       d.id_usuario_subida, d.activo,
                       res.nombre as nombre_residencia
                FROM documento d
                JOIN residencia res ON d.id_residencia = res.id_residencia
                WHERE d.activo = TRUE
                {residencias_filtro}
            """
            
            params_unificados = params.copy()
            
            # Filtros opcionales para documentos unificados
            if tipo_entidad:
                query_unificados += " AND d.tipo_entidad = %s"
                params_unificados.append(tipo_entidad)
            
            if categoria:
                query_unificados += " AND d.categoria_documento = %s"
                params_unificados.append(categoria)
            
            if id_entidad:
                query_unificados += " AND d.id_entidad = %s"
                params_unificados.append(id_entidad)
            
            # Segundo: documentos legacy de residentes (tabla documento_residente)
            # Construir filtro de residencias para documento_residente
            residencias_filtro_legacy = ""
            if residencias_filtro:
                # Construir el filtro con el alias correcto
                if g.id_rol != SUPER_ADMIN_ROLE_ID and g.residencias_acceso:
                    placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                    residencias_filtro_legacy = f" AND dr.id_residencia IN ({placeholders})"
            
            query_legacy = f"""
                SELECT dr.id_documento, 'residente' as tipo_entidad, dr.id_residente as id_entidad, 
                       dr.id_residencia,
                       COALESCE(dr.categoria_documento, 'otra') as categoria_documento, 
                       dr.tipo_documento, dr.nombre_archivo, dr.descripcion,
                       dr.fecha_subida, dr.url_archivo, dr.tamaño_bytes, dr.tipo_mime,
                       NULL as id_usuario_subida, TRUE as activo,
                       res.nombre as nombre_residencia
                FROM documento_residente dr
                JOIN residencia res ON dr.id_residencia = res.id_residencia
                WHERE 1=1
                {residencias_filtro_legacy}
            """
            
            params_legacy = params.copy()
            
            # Filtros opcionales para documentos legacy
            if tipo_entidad:
                if tipo_entidad == 'residente':
                    # Solo incluir documentos legacy si el filtro es 'residente'
                    pass  # Ya está incluido
                else:
                    # Si el filtro es otro tipo, no incluir documentos legacy
                    query_legacy = None
            else:
                # Si no hay filtro de tipo, incluir documentos legacy
                pass
            
            if categoria and query_legacy:
                # Para documentos legacy, mapear categorías si es necesario
                # Si el documento_residente no tiene categoria_documento, se asume 'otra'
                if categoria == 'otra':
                    # Incluir documentos sin categoría o con categoría 'otra'
                    query_legacy += " AND (dr.categoria_documento IS NULL OR dr.categoria_documento = 'otra')"
                else:
                    query_legacy += " AND dr.categoria_documento = %s"
                    params_legacy.append(categoria)
            
            if id_entidad and query_legacy:
                query_legacy += " AND dr.id_residente = %s"
                params_legacy.append(id_entidad)
            
            # Ejecutar consultas y combinar resultados
            documentos = []
            
            # Consultar documentos unificados
            cursor.execute(query_unificados, params_unificados)
            documentos.extend(cursor.fetchall())
            
            # Consultar documentos legacy (solo si no hay filtro de tipo o si es 'residente')
            if query_legacy and (not tipo_entidad or tipo_entidad == 'residente'):
                cursor.execute(query_legacy, params_legacy)
                documentos.extend(cursor.fetchall())
            
            # Ordenar por fecha_subida descendente
            documentos.sort(key=lambda x: x[8] if x[8] else datetime.min, reverse=True)
            
            # Obtener nombres de las entidades
            resultado = []
            for doc in documentos:
                tipo_ent = doc[1]
                id_ent = doc[2]
                nombre_entidad = None
                
                # Obtener nombre de la entidad
                try:
                    if tipo_ent == 'residente':
                        cursor.execute("SELECT nombre, apellido FROM residente WHERE id_residente = %s", (id_ent,))
                        ent = cursor.fetchone()
                        if ent:
                            nombre_entidad = f"{ent[0]} {ent[1]}"
                    elif tipo_ent == 'proveedor':
                        cursor.execute("SELECT nombre FROM proveedor WHERE id_proveedor = %s", (id_ent,))
                        ent = cursor.fetchone()
                        if ent:
                            nombre_entidad = ent[0]
                    elif tipo_ent == 'personal':
                        cursor.execute("SELECT nombre, apellido FROM personal WHERE id_personal = %s", (id_ent,))
                        ent = cursor.fetchone()
                        if ent:
                            nombre_entidad = f"{ent[0]} {ent[1]}"
                except:
                    pass
                
                url_descarga = None
                if doc[9]:  # Si hay url_archivo
                    url_descarga = get_document_url(doc[9], expiration_minutes=60)
                
                resultado.append({
                    'id_documento': doc[0],
                    'tipo_entidad': doc[1],
                    'id_entidad': doc[2],
                    'nombre_entidad': nombre_entidad,
                    'id_residencia': doc[3],
                    'nombre_residencia': doc[14],
                    'categoria_documento': doc[4],
                    'tipo_documento': doc[5],
                    'nombre_archivo': doc[6],
                    'descripcion': doc[7],
                    'fecha_subida': doc[8].isoformat() if doc[8] else None,
                    'url_archivo': doc[9],
                    'url_descarga': url_descarga,
                    'tamaño_bytes': doc[10],
                    'tipo_mime': doc[11],
                    'id_usuario_subida': doc[12]
                })
            
            return jsonify({
                'documentos': resultado,
                'total': len(resultado),
                'filtros': {
                    'tipo_entidad': tipo_entidad,
                    'categoria': categoria,
                    'id_entidad': id_entidad
                }
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar documentación: {str(e)}")
        return jsonify({'error': 'Error al obtener documentación'}), 500


@app.route('/api/v1/documentacion', methods=['POST'])
def crear_documento_unificado():
    """
    Crea un nuevo documento y lo sube a Cloud Storage.
    
    Request (multipart/form-data):
    - archivo: Archivo a subir
    - tipo_entidad: 'residente', 'proveedor', 'personal'
    - id_entidad: ID de la entidad
    - categoria_documento: 'medica', 'fiscal', 'sanitaria', 'laboral', 'otra'
    - tipo_documento: Tipo específico del documento
    - descripcion: Descripción opcional
    """
    try:
        if 'archivo' not in request.files:
            return jsonify({'error': 'Archivo requerido'}), 400
        
        archivo = request.files['archivo']
        if archivo.filename == '':
            return jsonify({'error': 'Nombre de archivo vacío'}), 400
        
        tipo_entidad = request.form.get('tipo_entidad')
        id_entidad = request.form.get('id_entidad', type=int)
        categoria_documento = request.form.get('categoria_documento')
        tipo_documento = request.form.get('tipo_documento')
        descripcion = request.form.get('descripcion', '')
        
        if not all([tipo_entidad, id_entidad, categoria_documento, tipo_documento]):
            return jsonify({'error': 'tipo_entidad, id_entidad, categoria_documento y tipo_documento son requeridos'}), 400
        
        if tipo_entidad not in ['residente', 'proveedor', 'personal']:
            return jsonify({'error': 'tipo_entidad debe ser: residente, proveedor o personal'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que la entidad existe y obtener su residencia
            id_residencia = None
            if tipo_entidad == 'residente':
                cursor.execute("SELECT id_residencia FROM residente WHERE id_residente = %s", (id_entidad,))
                res = cursor.fetchone()
                if not res:
                    return jsonify({'error': 'Residente no encontrado'}), 404
                id_residencia = res[0]
            elif tipo_entidad == 'proveedor':
                cursor.execute("SELECT id_residencia FROM proveedor WHERE id_proveedor = %s", (id_entidad,))
                res = cursor.fetchone()
                if not res:
                    return jsonify({'error': 'Proveedor no encontrado'}), 404
                id_residencia = res[0]
            elif tipo_entidad == 'personal':
                cursor.execute("SELECT id_residencia FROM personal WHERE id_personal = %s", (id_entidad,))
                res = cursor.fetchone()
                if not res:
                    return jsonify({'error': 'Personal no encontrado'}), 404
                id_residencia = res[0]
            
            # Verificar permisos de acceso a la residencia
            is_valid, error_response = validate_residencia_access(id_residencia)
            if not is_valid:
                return error_response
            
            # Leer contenido del archivo
            file_content = archivo.read()
            nombre_archivo = archivo.filename
            content_type = archivo.content_type
            
            # Subir a Cloud Storage usando función unificada
            from storage_manager import upload_document_unificado
            blob_path = upload_document_unificado(
                file_content, id_residencia, tipo_entidad, id_entidad,
                tipo_documento, nombre_archivo, content_type
            )
            
            if not blob_path:
                return jsonify({'error': 'Error al subir el archivo a Cloud Storage'}), 500
            
            # Guardar en base de datos
            cursor.execute("""
                INSERT INTO documento (tipo_entidad, id_entidad, id_residencia, categoria_documento,
                                      tipo_documento, nombre_archivo, descripcion, url_archivo,
                                      tamaño_bytes, tipo_mime, id_usuario_subida, activo)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
                RETURNING id_documento, fecha_subida
            """, (
                tipo_entidad, id_entidad, id_residencia, categoria_documento,
                tipo_documento, nombre_archivo, descripcion, blob_path,
                len(file_content), content_type, g.id_usuario
            ))
            
            resultado = cursor.fetchone()
            id_documento = resultado[0]
            conn.commit()
            
            return jsonify({
                'id_documento': id_documento,
                'mensaje': 'Documento subido exitosamente',
                'url_archivo': blob_path
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear documento: {str(e)}")
            return jsonify({'error': f'Error al crear documento: {str(e)}'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/documentacion/<int:id_documento>', methods=['DELETE'])
def eliminar_documento_unificado(id_documento):
    """Elimina un documento unificado (marca como inactivo y elimina de Cloud Storage)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Buscar primero en la tabla unificada 'documento'
            cursor.execute("""
                SELECT id_documento, url_archivo, id_residencia, tipo_entidad, id_entidad, 'documento' as tabla_origen
                FROM documento 
                WHERE id_documento = %s AND activo = TRUE
            """, (id_documento,))
            
            doc = cursor.fetchone()
            tabla_origen = 'documento'
            
            # Si no se encuentra, buscar en documento_residente (legacy)
            if not doc:
                cursor.execute("""
                    SELECT id_documento, url_archivo, id_residencia, 'residente' as tipo_entidad, id_residente as id_entidad, 'documento_residente' as tabla_origen
                    FROM documento_residente 
                    WHERE id_documento = %s
                """, (id_documento,))
                
                doc = cursor.fetchone()
                tabla_origen = 'documento_residente'
            
            if not doc:
                return jsonify({'error': 'Documento no encontrado'}), 404
            
            id_residencia = doc[2]
            
            # Verificar permisos
            is_valid, error_response = validate_residencia_access(id_residencia)
            if not is_valid:
                return error_response
            
            # Eliminar de Cloud Storage
            if doc[1]:  # Si hay url_archivo
                delete_document(doc[1])
            
            # Eliminar según la tabla de origen
            if tabla_origen == 'documento':
                # Marcar como inactivo (soft delete)
                cursor.execute("""
                    UPDATE documento
                    SET activo = FALSE
                    WHERE id_documento = %s
                    RETURNING id_documento
                """, (id_documento,))
            else:
                # Eliminar físicamente de documento_residente
                cursor.execute("""
                    DELETE FROM documento_residente
                    WHERE id_documento = %s
                    RETURNING id_documento
                """, (id_documento,))
            
            conn.commit()
            
            return jsonify({
                'mensaje': 'Documento eliminado exitosamente'
            }), 200
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al eliminar documento: {str(e)}")
            return jsonify({'error': 'Error al eliminar documento'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/v1/documentacion/<int:id_documento>/descargar', methods=['GET'])
def descargar_documento_unificado(id_documento):
    """Genera una URL firmada para descargar un documento."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Buscar primero en la tabla unificada 'documento'
            cursor.execute("""
                SELECT url_archivo, id_residencia FROM documento
                WHERE id_documento = %s AND activo = TRUE
            """, (id_documento,))
            
            doc = cursor.fetchone()
            
            # Si no se encuentra, buscar en documento_residente (legacy)
            if not doc:
                cursor.execute("""
                    SELECT url_archivo, id_residencia FROM documento_residente
                    WHERE id_documento = %s
                """, (id_documento,))
                
                doc = cursor.fetchone()
            
            if not doc:
                return jsonify({'error': 'Documento no encontrado'}), 404
            
            # Verificar permisos
            is_valid, error_response = validate_residencia_access(doc[1])
            if not is_valid:
                return error_response
            
            url_descarga = get_document_url(doc[0], expiration_minutes=60)
            
            if not url_descarga:
                return jsonify({'error': 'Error al generar URL de descarga'}), 500
            
            return jsonify({
                'url_descarga': url_descarga,
                'expira_en_minutos': 60
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al generar URL de descarga: {str(e)}")
        return jsonify({'error': 'Error al generar URL de descarga'}), 500


@app.route('/api/v1/documentacion/categorias', methods=['GET'])
def listar_categorias():
    """Lista las categorías de documentos disponibles."""
    categorias = [
        {'valor': 'medica', 'nombre': 'Médica'},
        {'valor': 'fiscal', 'nombre': 'Fiscal'},
        {'valor': 'sanitaria', 'nombre': 'Sanitaria'},
        {'valor': 'laboral', 'nombre': 'Laboral'},
        {'valor': 'otra', 'nombre': 'Otra'}
    ]
    return jsonify({'categorias': categorias}), 200


@app.route('/api/v1/documentacion/tipos-entidad', methods=['GET'])
def listar_tipos_entidad():
    """Lista los tipos de entidades disponibles."""
    tipos = [
        {'valor': 'residente', 'nombre': 'Residente'},
        {'valor': 'proveedor', 'nombre': 'Proveedor'},
        {'valor': 'personal', 'nombre': 'Personal'}
    ]
    return jsonify({'tipos': tipos}), 200


# ============================================================================
# ENDPOINTS DE HISTÓRICOS - COBROS Y PAGOS
# ============================================================================

@app.route('/api/v1/historicos', methods=['GET'])
def listar_historicos():
    """
    Lista todos los cobros y pagos históricos con filtros opcionales.
    
    Query params:
    - tipo: 'cobros', 'pagos', 'todos' (default: 'todos')
    - fecha_desde: Fecha inicio (YYYY-MM-DD)
    - fecha_hasta: Fecha fin (YYYY-MM-DD)
    - id_residencia: ID de residencia (opcional)
    - estado: 'pendiente', 'cobrado', 'pagado' (opcional)
    - exportar: 'pdf', 'excel' (opcional, si se especifica genera el archivo)
    """
    try:
        tipo = request.args.get('tipo', 'todos')  # 'cobros', 'pagos', 'todos'
        fecha_desde = request.args.get('fecha_desde')
        fecha_hasta = request.args.get('fecha_hasta')
        id_residencia_filtro = request.args.get('id_residencia', type=int)
        estado_filtro = request.args.get('estado')
        exportar = request.args.get('exportar')  # 'pdf' o 'excel'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cobros = []
            pagos = []
            
            # Obtener cobros (pago_residente)
            if tipo in ['cobros', 'todos']:
                query_cobros = """
                    SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                           p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                           p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, 
                           p.fecha_creacion, res.id_residencia, res.nombre as nombre_residencia
                    FROM pago_residente p
                    JOIN residente r ON p.id_residente = r.id_residente
                    JOIN residencia res ON p.id_residencia = res.id_residencia
                    WHERE 1=1
                """
                params_cobros = []
                
                # Filtrar por residencias de acceso
                if g.id_rol != SUPER_ADMIN_ROLE_ID:
                    if g.residencias_acceso:
                        placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                        query_cobros += f" AND p.id_residencia IN ({placeholders})"
                        params_cobros.extend(g.residencias_acceso)
                    else:
                        query_cobros += " AND FALSE"  # Sin acceso
                
                if id_residencia_filtro:
                    query_cobros += " AND p.id_residencia = %s"
                    params_cobros.append(id_residencia_filtro)
                
                if fecha_desde:
                    query_cobros += " AND (p.fecha_pago >= %s OR p.fecha_prevista >= %s OR (p.fecha_pago IS NULL AND p.fecha_prevista IS NULL AND p.fecha_creacion::date >= %s))"
                    params_cobros.extend([fecha_desde, fecha_desde, fecha_desde])
                
                if fecha_hasta:
                    query_cobros += " AND (p.fecha_pago <= %s OR p.fecha_prevista <= %s OR (p.fecha_pago IS NULL AND p.fecha_prevista IS NULL AND p.fecha_creacion::date <= %s))"
                    params_cobros.extend([fecha_hasta, fecha_hasta, fecha_hasta])
                
                if estado_filtro:
                    query_cobros += " AND p.estado = %s"
                    params_cobros.append(estado_filtro)
                
                query_cobros += " ORDER BY COALESCE(p.fecha_pago, p.fecha_prevista, p.fecha_creacion::date) DESC, p.fecha_creacion DESC"
                
                cursor.execute(query_cobros, params_cobros)
                cobros_raw = cursor.fetchall()
                
                for cobro in cobros_raw:
                    cobros.append({
                        'id_pago': cobro[0],
                        'id_residente': cobro[1],
                        'residente': cobro[2],
                        'monto': float(cobro[3]) if cobro[3] else 0,
                        'fecha_pago': cobro[4].isoformat() if cobro[4] else None,
                        'fecha_prevista': cobro[5].isoformat() if cobro[5] else None,
                        'mes_pagado': cobro[6],
                        'concepto': cobro[7],
                        'metodo_pago': cobro[8],
                        'estado': cobro[9],
                        'es_cobro_previsto': cobro[10],
                        'observaciones': cobro[11],
                        'fecha_creacion': cobro[12].isoformat() if cobro[12] else None,
                        'id_residencia': cobro[13],
                        'nombre_residencia': cobro[14],
                        'tipo': 'cobro'
                    })
            
            # Obtener pagos (pago_proveedor)
            if tipo in ['pagos', 'todos']:
                query_pagos = """
                    SELECT p.id_pago, p.proveedor, p.concepto, p.monto, p.fecha_pago, 
                           p.fecha_prevista, p.metodo_pago, p.estado, p.numero_factura,
                           p.es_estimacion, p.observaciones, p.fecha_creacion,
                           res.id_residencia, res.nombre as nombre_residencia
                    FROM pago_proveedor p
                    JOIN residencia res ON p.id_residencia = res.id_residencia
                    WHERE 1=1
                """
                params_pagos = []
                
                # Filtrar por residencias de acceso
                if g.id_rol != SUPER_ADMIN_ROLE_ID:
                    if g.residencias_acceso:
                        placeholders = ','.join(['%s'] * len(g.residencias_acceso))
                        query_pagos += f" AND p.id_residencia IN ({placeholders})"
                        params_pagos.extend(g.residencias_acceso)
                    else:
                        query_pagos += " AND FALSE"  # Sin acceso
                
                if id_residencia_filtro:
                    query_pagos += " AND p.id_residencia = %s"
                    params_pagos.append(id_residencia_filtro)
                
                if fecha_desde:
                    query_pagos += " AND (p.fecha_pago >= %s OR p.fecha_prevista >= %s OR (p.fecha_pago IS NULL AND p.fecha_prevista IS NULL AND p.fecha_creacion::date >= %s))"
                    params_pagos.extend([fecha_desde, fecha_desde, fecha_desde])
                
                if fecha_hasta:
                    query_pagos += " AND (p.fecha_pago <= %s OR p.fecha_prevista <= %s OR (p.fecha_pago IS NULL AND p.fecha_prevista IS NULL AND p.fecha_creacion::date <= %s))"
                    params_pagos.extend([fecha_hasta, fecha_hasta, fecha_hasta])
                
                if estado_filtro:
                    query_pagos += " AND p.estado = %s"
                    params_pagos.append(estado_filtro)
                
                query_pagos += " ORDER BY COALESCE(p.fecha_pago, p.fecha_prevista, p.fecha_creacion::date) DESC, p.fecha_creacion DESC"
                
                cursor.execute(query_pagos, params_pagos)
                pagos_raw = cursor.fetchall()
                
                for pago in pagos_raw:
                    pagos.append({
                        'id_pago': pago[0],
                        'proveedor': pago[1],
                        'concepto': pago[2],
                        'monto': float(pago[3]) if pago[3] else 0,
                        'fecha_pago': pago[4].isoformat() if pago[4] else None,
                        'fecha_prevista': pago[5].isoformat() if pago[5] else None,
                        'metodo_pago': pago[6],
                        'estado': pago[7],
                        'numero_factura': pago[8],
                        'es_estimacion': pago[9],
                        'observaciones': pago[10],
                        'fecha_creacion': pago[11].isoformat() if pago[11] else None,
                        'id_residencia': pago[12],
                        'nombre_residencia': pago[13],
                        'tipo': 'pago'
                    })
            
            # Si se solicita exportación, generar archivo
            if exportar == 'pdf':
                return generar_pdf_historicos(cobros, pagos, fecha_desde, fecha_hasta)
            elif exportar == 'excel':
                return generar_excel_historicos(cobros, pagos, fecha_desde, fecha_hasta)
            
            # Retornar JSON
            return jsonify({
                'cobros': cobros,
                'pagos': pagos,
                'total_cobros': len(cobros),
                'total_pagos': len(pagos),
                'total_cobros_monto': sum(c['monto'] for c in cobros),
                'total_pagos_monto': sum(p['monto'] for p in pagos),
                'filtros': {
                    'tipo': tipo,
                    'fecha_desde': fecha_desde,
                    'fecha_hasta': fecha_hasta,
                    'id_residencia': id_residencia_filtro,
                    'estado': estado_filtro
                }
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar históricos: {str(e)}")
        return jsonify({'error': 'Error al obtener históricos'}), 500


def generar_pdf_historicos(cobros, pagos, fecha_desde=None, fecha_hasta=None):
    """Genera un PDF con los históricos de cobros y pagos."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
        elements = []
        styles = getSampleStyleSheet()
        
        # Título
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=30,
            alignment=1  # Centrado
        )
        elements.append(Paragraph("Histórico de Cobros y Pagos", title_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Información de filtros
        if fecha_desde or fecha_hasta:
            filtro_text = "Período: "
            if fecha_desde:
                filtro_text += f"Desde {fecha_desde}"
            if fecha_hasta:
                filtro_text += f" Hasta {fecha_hasta}"
            elements.append(Paragraph(filtro_text, styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        # Cobros
        if cobros:
            elements.append(Paragraph(f"<b>COBROS A RESIDENTES ({len(cobros)})</b>", styles['Heading2']))
            elements.append(Spacer(1, 0.1*inch))
            
            data_cobros = [['Residente', 'Monto', 'Fecha Pago', 'Estado', 'Concepto']]
            for cobro in cobros:
                fecha = cobro.get('fecha_pago') or cobro.get('fecha_prevista') or '-'
                if fecha and fecha != '-':
                    fecha = fecha.split('T')[0] if 'T' in str(fecha) else fecha
                data_cobros.append([
                    cobro.get('residente', '-'),
                    f"€{cobro.get('monto', 0):.2f}",
                    fecha,
                    cobro.get('estado', '-'),
                    cobro.get('concepto', '-')[:50]
                ])
            
            table_cobros = Table(data_cobros, colWidths=[2*inch, 1*inch, 1*inch, 1*inch, 2*inch])
            table_cobros.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            elements.append(table_cobros)
            elements.append(Spacer(1, 0.2*inch))
            
            # Total cobros
            total_cobros = sum(c.get('monto', 0) for c in cobros)
            elements.append(Paragraph(f"<b>Total Cobros: €{total_cobros:.2f}</b>", styles['Normal']))
            elements.append(Spacer(1, 0.2*inch))
        
        # Pagos
        if pagos:
            if cobros:
                elements.append(PageBreak())
            elements.append(Paragraph(f"<b>PAGOS A PROVEEDORES ({len(pagos)})</b>", styles['Heading2']))
            elements.append(Spacer(1, 0.1*inch))
            
            data_pagos = [['Proveedor', 'Monto', 'Fecha Pago', 'Estado', 'Concepto']]
            for pago in pagos:
                fecha = pago.get('fecha_pago') or pago.get('fecha_prevista') or '-'
                if fecha and fecha != '-':
                    fecha = fecha.split('T')[0] if 'T' in str(fecha) else fecha
                data_pagos.append([
                    pago.get('proveedor', '-'),
                    f"€{pago.get('monto', 0):.2f}",
                    fecha,
                    pago.get('estado', '-'),
                    pago.get('concepto', '-')[:50]
                ])
            
            table_pagos = Table(data_pagos, colWidths=[2*inch, 1*inch, 1*inch, 1*inch, 2*inch])
            table_pagos.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            elements.append(table_pagos)
            elements.append(Spacer(1, 0.2*inch))
            
            # Total pagos
            total_pagos = sum(p.get('monto', 0) for p in pagos)
            elements.append(Paragraph(f"<b>Total Pagos: €{total_pagos:.2f}</b>", styles['Normal']))
        
        # Pie de página
        elements.append(Spacer(1, 0.3*inch))
        fecha_generacion = datetime.now().strftime('%d/%m/%Y %H:%M')
        elements.append(Paragraph(f"Generado el {fecha_generacion}", styles['Normal']))
        
        doc.build(elements)
        buffer.seek(0)
        
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=historicos_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            }
        )
        
    except ImportError:
        app.logger.error("reportlab no está instalado. Instale con: pip install reportlab")
        return jsonify({'error': 'Generación de PDF no disponible. Instale reportlab.'}), 500
    except Exception as e:
        app.logger.error(f"Error al generar PDF: {str(e)}")
        return jsonify({'error': f'Error al generar PDF: {str(e)}'}), 500


def generar_excel_historicos(cobros, pagos, fecha_desde=None, fecha_hasta=None):
    """Genera un archivo Excel con los históricos de cobros y pagos."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        
        wb = Workbook()
        ws = wb.active
        ws.title = "Históricos"
        
        # Estilos
        header_fill = PatternFill(start_color="667eea", end_color="667eea", fill_type="solid")
        header_font = Font(bold=True, color="FFFFFF", size=12)
        border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
        
        row = 1
        
        # Título
        ws.merge_cells(f'A{row}:E{row}')
        cell = ws[f'A{row}']
        cell.value = "Histórico de Cobros y Pagos"
        cell.font = Font(bold=True, size=16, color="667eea")
        cell.alignment = Alignment(horizontal='center', vertical='center')
        row += 2
        
        # Filtros
        if fecha_desde or fecha_hasta:
            filtro_text = "Período: "
            if fecha_desde:
                filtro_text += f"Desde {fecha_desde}"
            if fecha_hasta:
                filtro_text += f" Hasta {fecha_hasta}"
            ws[f'A{row}'] = filtro_text
            row += 2
        
        # Cobros
        if cobros:
            ws[f'A{row}'] = f"COBROS A RESIDENTES ({len(cobros)})"
            ws[f'A{row}'].font = Font(bold=True, size=14)
            row += 1
            
            # Encabezados
            headers = ['Residente', 'Monto', 'Fecha Pago', 'Estado', 'Concepto', 'Método Pago', 'Residencia']
            for col, header in enumerate(headers, 1):
                cell = ws.cell(row=row, column=col)
                cell.value = header
                cell.fill = header_fill
                cell.font = header_font
                cell.border = border
                cell.alignment = Alignment(horizontal='center', vertical='center')
            row += 1
            
            # Datos
            for cobro in cobros:
                fecha = cobro.get('fecha_pago') or cobro.get('fecha_prevista') or ''
                if fecha and 'T' in str(fecha):
                    fecha = fecha.split('T')[0]
                
                ws.cell(row=row, column=1, value=cobro.get('residente', ''))
                ws.cell(row=row, column=2, value=f"€{cobro.get('monto', 0):.2f}")
                ws.cell(row=row, column=3, value=fecha)
                ws.cell(row=row, column=4, value=cobro.get('estado', ''))
                ws.cell(row=row, column=5, value=cobro.get('concepto', ''))
                ws.cell(row=row, column=6, value=cobro.get('metodo_pago', ''))
                ws.cell(row=row, column=7, value=cobro.get('nombre_residencia', ''))
                
                for col in range(1, 8):
                    ws.cell(row=row, column=col).border = border
                row += 1
            
            # Total
            total_cobros = sum(c.get('monto', 0) for c in cobros)
            ws.cell(row=row, column=1, value="TOTAL COBROS").font = Font(bold=True)
            ws.cell(row=row, column=2, value=f"€{total_cobros:.2f}").font = Font(bold=True)
            row += 2
        
        # Pagos
        if pagos:
            ws[f'A{row}'] = f"PAGOS A PROVEEDORES ({len(pagos)})"
            ws[f'A{row}'].font = Font(bold=True, size=14)
            row += 1
            
            # Encabezados
            headers = ['Proveedor', 'Monto', 'Fecha Pago', 'Estado', 'Concepto', 'Nº Factura', 'Residencia']
            for col, header in enumerate(headers, 1):
                cell = ws.cell(row=row, column=col)
                cell.value = header
                cell.fill = header_fill
                cell.font = header_font
                cell.border = border
                cell.alignment = Alignment(horizontal='center', vertical='center')
            row += 1
            
            # Datos
            for pago in pagos:
                fecha = pago.get('fecha_pago') or pago.get('fecha_prevista') or ''
                if fecha and 'T' in str(fecha):
                    fecha = fecha.split('T')[0]
                
                ws.cell(row=row, column=1, value=pago.get('proveedor', ''))
                ws.cell(row=row, column=2, value=f"€{pago.get('monto', 0):.2f}")
                ws.cell(row=row, column=3, value=fecha)
                ws.cell(row=row, column=4, value=pago.get('estado', ''))
                ws.cell(row=row, column=5, value=pago.get('concepto', ''))
                ws.cell(row=row, column=6, value=pago.get('numero_factura', ''))
                ws.cell(row=row, column=7, value=pago.get('nombre_residencia', ''))
                
                for col in range(1, 8):
                    ws.cell(row=row, column=col).border = border
                row += 1
            
            # Total
            total_pagos = sum(p.get('monto', 0) for p in pagos)
            ws.cell(row=row, column=1, value="TOTAL PAGOS").font = Font(bold=True)
            ws.cell(row=row, column=2, value=f"€{total_pagos:.2f}").font = Font(bold=True)
        
        # Ajustar ancho de columnas
        ws.column_dimensions['A'].width = 25
        ws.column_dimensions['B'].width = 15
        ws.column_dimensions['C'].width = 15
        ws.column_dimensions['D'].width = 15
        ws.column_dimensions['E'].width = 30
        ws.column_dimensions['F'].width = 15
        ws.column_dimensions['G'].width = 20
        
        buffer = BytesIO()
        wb.save(buffer)
        buffer.seek(0)
        
        return Response(
            buffer.getvalue(),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename=historicos_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
            }
        )
        
    except ImportError:
        app.logger.error("openpyxl no está instalado. Instale con: pip install openpyxl")
        return jsonify({'error': 'Generación de Excel no disponible. Instale openpyxl.'}), 500
    except Exception as e:
        app.logger.error(f"Error al generar Excel: {str(e)}")
        return jsonify({'error': f'Error al generar Excel: {str(e)}'}), 500


if __name__ == '__main__':
    # Configurar logging para mostrar en consola
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Para desarrollo local
    print("\n" + "="*50)
    print("  Servidor Flask Violetas iniciado")
    print("="*50)
    print(f"  URL: http://localhost:5000")
    print(f"  Modo: DEBUG")
    print(f"  Presiona Ctrl+C para detener")
    print("="*50 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)

