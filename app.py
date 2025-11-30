"""
Aplicación principal Flask para el sistema de gestión de residencias Violetas.
Implementa autenticación JWT y filtrado de datos por residencia.
"""
import os
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from db_connector import get_db_connection
from storage_manager import upload_document, get_document_url, delete_document
from validators import (
    validate_residente_data, validate_cobro_data, validate_monto,
    validate_residencia_id, validate_estado, validate_metodo_pago,
    validate_text, validate_email, validate_phone
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
            
    except ValueError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        app.logger.error(f"Error en login: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# ============================================================================
# ENDPOINTS DE RESIDENTES
# ============================================================================

@app.route('/api/v1/residencias/<int:id_residencia>/habitaciones-ocupadas', methods=['GET'])
def obtener_habitaciones_ocupadas(id_residencia):
    """Obtiene las habitaciones ocupadas de una residencia (solo residentes activos)."""
    try:
        # Verificar que el usuario tenga acceso a esta residencia
        if id_residencia != g.id_residencia:
            return jsonify({'error': 'No tienes permisos para acceder a esta residencia'}), 403
        
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
            
            # Filtrar por residencia si NO es Admin (rol 1)
            if g.id_rol != 1:
                query += f" WHERE r.id_residencia = {g.id_residencia}"
            
            query += """
                ORDER BY r.id_residencia, 
                         CASE 
                             WHEN r.habitacion ~ '^[0-9]+$' THEN r.habitacion::INTEGER
                             ELSE 999999
                         END,
                         r.habitacion
            """
            
            cursor.execute(query)
            
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
            # Verificar que el residente existe y está activo
            cursor.execute("""
                SELECT id_residente, activo FROM residente
                WHERE id_residente = %s
            """, (id_residente,))
            
            residente = cursor.fetchone()
            if not residente:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            if not residente[1]:  # Si ya está inactivo
                return jsonify({'error': 'El residente ya está dado de baja'}), 400
            
            # Actualizar el residente: activo = False, motivo_baja, fecha_baja = hoy
            from datetime import date
            fecha_baja = date.today()
            
            cursor.execute("""
                UPDATE residente
                SET activo = FALSE,
                    motivo_baja = %s,
                    fecha_baja = %s
                WHERE id_residente = %s
                RETURNING id_residente
            """, (motivo_baja, fecha_baja, id_residente))
            
            conn.commit()
            
            return jsonify({
                'mensaje': 'Residente dado de baja exitosamente',
                'id_residente': id_residente,
                'motivo_baja': motivo_baja,
                'fecha_baja': str(fecha_baja)
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
    """Lista los pagos de residentes de la residencia del usuario."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Si es Admin (rol 1), ve todo. Si no, solo su residencia.
            if g.id_rol == 1:
                cursor.execute("""
                    SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                           p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                           p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion,
                           res.id_residencia, res.nombre as nombre_residencia
                    FROM pago_residente p
                    JOIN residente r ON p.id_residente = r.id_residente
                    JOIN residencia res ON p.id_residencia = res.id_residencia
                    ORDER BY res.id_residencia, 
                             CASE 
                                 WHEN p.fecha_prevista IS NOT NULL THEN p.fecha_prevista
                                 WHEN p.fecha_pago IS NOT NULL THEN p.fecha_pago
                                 ELSE '9999-12-31'::date
                             END ASC,
                             p.fecha_creacion DESC
                """)
            else:
                cursor.execute("""
                    SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                           p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                           p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion,
                           res.id_residencia, res.nombre as nombre_residencia
                    FROM pago_residente p
                    JOIN residente r ON p.id_residente = r.id_residente
                    JOIN residencia res ON p.id_residencia = res.id_residencia
                    WHERE p.id_residencia = %s
                    ORDER BY 
                             CASE 
                                 WHEN p.fecha_prevista IS NOT NULL THEN p.fecha_prevista
                                 WHEN p.fecha_pago IS NOT NULL THEN p.fecha_pago
                                 ELSE '9999-12-31'::date
                             END ASC,
                             p.fecha_creacion DESC
                """, (g.id_residencia,))
            
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
            # Verificar que el residente pertenece a la residencia
            cursor.execute("""
                SELECT id_residente FROM residente
                WHERE id_residente = %s AND id_residencia = %s
            """, (id_residente, g.id_residencia))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            # Determinar estado: si tiene fecha_pago, es cobrado; si no, es pendiente
            estado_final = data.get('estado')
            if not estado_final:
                if fecha_pago:
                    estado_final = 'cobrado'
                else:
                    estado_final = 'pendiente'
            
            cursor.execute("""
                INSERT INTO pago_residente (id_residente, id_residencia, monto, fecha_pago, fecha_prevista,
                                          mes_pagado, concepto, metodo_pago, estado, es_cobro_previsto, observaciones)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_pago
            """, (
                id_residente,
                g.id_residencia,
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
    Genera automáticamente cobros previstos para todos los residentes activos
    que tengan costo_habitacion definido.
    
    Lógica: Si un residente NO tiene un cobro completado en el mes actual,
    se genera un cobro previsto para ese mes.
    
    La fecha prevista se calcula según el metodo_pago_preferido:
    - transferencia: día 3 del mes
    - remesa: día 30 del mes
    - otros: día 5 del mes (por defecto)
    
    Por defecto genera para el mes actual (no el siguiente).
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
            # Si es Admin, limpia de TODAS las residencias. Si no, solo de la suya.
            if g.id_rol == 1:
                cursor.execute("""
                    DELETE FROM pago_residente
                    WHERE es_cobro_previsto = TRUE
                      AND estado = 'pendiente'
                """)
            else:
                cursor.execute("""
                    DELETE FROM pago_residente
                    WHERE id_residencia = %s
                      AND es_cobro_previsto = TRUE
                      AND estado = 'pendiente'
                """, (g.id_residencia,))
            
            cobros_eliminados = cursor.rowcount
            
            # Calcular mes siguiente (una sola vez)
            hoy = datetime.now()
            mes_actual = hoy.month
            año_actual = hoy.year
            
            if mes_actual == 12:
                siguiente_mes = datetime(año_actual + 1, 1, 1)
            else:
                siguiente_mes = datetime(año_actual, mes_actual + 1, 1)
            
            # Obtener residentes activos con costo_habitacion
            # Si es Admin, obtiene de TODAS las residencias. Si no, solo de la suya.
            if g.id_rol == 1:
                cursor.execute("""
                    SELECT id_residente, nombre, apellido, costo_habitacion, metodo_pago_preferido, fecha_ingreso, id_residencia
                    FROM residente
                    WHERE activo = TRUE 
                      AND costo_habitacion IS NOT NULL 
                      AND costo_habitacion > 0
                      AND fecha_ingreso IS NOT NULL
                """)
            else:
                cursor.execute("""
                    SELECT id_residente, nombre, apellido, costo_habitacion, metodo_pago_preferido, fecha_ingreso, id_residencia
                    FROM residente
                    WHERE id_residencia = %s 
                      AND activo = TRUE 
                      AND costo_habitacion IS NOT NULL 
                      AND costo_habitacion > 0
                      AND fecha_ingreso IS NOT NULL
                """, (g.id_residencia,))
            
            residentes = cursor.fetchall()
            
            # Verificar cuántos residentes hay en total (para diagnóstico)
            if g.id_rol == 1:
                cursor.execute("SELECT COUNT(*) FROM residente WHERE activo = TRUE")
                total_residentes_activos = cursor.fetchone()[0]
                app.logger.info(f"Generando cobros previstos GLOBAL (Admin)")
            else:
                cursor.execute("SELECT COUNT(*) FROM residente WHERE id_residencia = %s AND activo = TRUE", (g.id_residencia,))
                total_residentes_activos = cursor.fetchone()[0]
                app.logger.info(f"Generando cobros previstos para residencia {g.id_residencia}")

            app.logger.info(f"Total residentes activos en alcance: {total_residentes_activos}")
            app.logger.info(f"Residentes candidatos encontrados (con costo y fecha_ingreso): {len(residentes)}")
            app.logger.info(f"Mes siguiente: {mes_siguiente}")
            
            if not residentes:
                return jsonify({
                    'mensaje': 'No hay residentes activos con costo_habitacion definido que deban tener cobros previstos',
                    'cobros_generados': 0,
                    'cobros_eliminados': cobros_eliminados,
                    'mes_referencia': mes_siguiente,
                    'total_residentes_activos': total_residentes_activos,
                    'residentes_candidatos': 0
                }), 200
            
            cobros_generados = 0
            cobros_duplicados = 0
            errores = []
            residentes_procesados = []
            
            for residente in residentes:
                id_residente = residente[0]
                nombre = residente[1]
                apellido = residente[2]
                costo_habitacion = float(residente[3])
                metodo_pago = residente[4] or 'transferencia'  # Por defecto transferencia
                fecha_ingreso = residente[5]  # fecha_ingreso del residente
                residencia_del_residente = residente[6] # ID de la residencia del residente actual
                
                # Lógica simple: Si el residente ingresó en o antes de hoy, debe tener cobro previsto
                # (a menos que ya tenga un cobro completado, lo cual se verifica más abajo)
                # No necesitamos validar fecha_ingreso aquí porque:
                # - Si ingresó hoy o antes, debe tener cobro previsto
                # - Si ingresó en el futuro (imposible por validación), no debería estar activo
                # La única excepción es si ya tiene un cobro completado para ese mes
                
                # Calcular fecha prevista según método de pago
                # Lógica:
                # - Remesa: día 30 del mes ACTUAL, pero mes_pagado es el mes SIGUIENTE
                # - Transferencia/otros: días 1-5 del mes SIGUIENTE, mes_pagado es el mes SIGUIENTE
                
                if metodo_pago.lower() in ['remesa']:
                    # Remesa: día 30 del mes actual, pero el pago es para el mes siguiente
                    # Calcular último día del mes actual
                    ultimo_dia = (siguiente_mes - timedelta(days=1)).day
                    dia_remesa = min(30, ultimo_dia)
                    fecha_prevista = datetime(año_actual, mes_actual, dia_remesa)
                    # Mes pagado es el mes siguiente
                    mes_pagado = siguiente_mes.strftime('%Y-%m')
                elif metodo_pago.lower() in ['transferencia', 'transfer']:
                    # Transferencia: días 1-5 del mes SIGUIENTE, mes_pagado es el mes SIGUIENTE
                    fecha_prevista = datetime(siguiente_mes.year, siguiente_mes.month, 3)  # Día 3 como valor medio
                    mes_pagado = siguiente_mes.strftime('%Y-%m')
                else:
                    # Otros métodos (metálico, bizum, etc.): días 1-5 del mes SIGUIENTE
                    fecha_prevista = datetime(siguiente_mes.year, siguiente_mes.month, 5)
                    mes_pagado = siguiente_mes.strftime('%Y-%m')
                
                # Verificar si el residente ya tiene un cobro COMPLETADO en este mes
                # Si tiene cobro completado, NO generar cobro previsto
                cursor.execute("""
                    SELECT id_pago FROM pago_residente
                    WHERE id_residente = %s 
                      AND id_residencia = %s
                      AND mes_pagado = %s
                      AND estado = 'cobrado'
                """, (id_residente, residencia_del_residente, mes_pagado))
                
                if cursor.fetchone():
                    # Ya tiene cobro completado en este mes, no generar previsto
                    cobros_duplicados += 1
                    app.logger.info(f"Residente {nombre} {apellido} (ID: {id_residente}) ya tiene cobro completado para {mes_pagado}")
                    continue
                
                # NO verificar duplicados de previstos - permitir acumulación
                # Los cobros previstos se acumulan si no se completan
                
                # Generar concepto con el nombre del mes
                meses_espanol = {
                    1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril',
                    5: 'mayo', 6: 'junio', 7: 'julio', 8: 'agosto',
                    9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'
                }
                nombre_mes = meses_espanol.get(siguiente_mes.month, 'mes')
                concepto = f"Pago {nombre_mes}"
                
                # Crear el cobro previsto
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
                        fecha_prevista.date(),
                        mes_pagado,
                        concepto,
                        metodo_pago,
                        'pendiente',
                        True
                    ))
                    
                    cobros_generados += 1
                    residentes_procesados.append(f"{nombre} {apellido} (ID: {id_residente})")
                    app.logger.info(f"Cobro previsto generado para {nombre} {apellido} (ID: {id_residente}): €{costo_habitacion}, mes: {mes_pagado}")
                    
                except Exception as e:
                    errores.append(f"Error al crear cobro para {nombre} {apellido}: {str(e)}")
                    app.logger.error(f"Error al crear cobro previsto para residente {id_residente}: {str(e)}")
            
            conn.commit()
            
            resultado = {
                'mensaje': f'Cobros previstos generados exitosamente',
                'cobros_generados': cobros_generados,
                'cobros_eliminados': cobros_eliminados,
                'cobros_duplicados': cobros_duplicados,
                'mes_referencia': mes_siguiente,
                'total_residentes_procesados': len(residentes),
                'total_residentes_candidatos': len(residentes),
                'residentes_procesados': residentes_procesados
            }
            
            app.logger.info(f"Resumen: {cobros_generados} cobros generados, {cobros_duplicados} duplicados, {len(residentes)} candidatos")
            
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
            # Obtener cobros históricos (cobrados) agrupados por mes
            # Para remesas cobradas el día 30, usar mes_pagado (mes siguiente)
            # Para otros casos, usar fecha_pago
            cursor.execute("""
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
                WHERE id_residencia = %s 
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
            """, (g.id_residencia,))
            
            historico = cursor.fetchall()
            
            # Obtener estimaciones futuras (cobros previstos pendientes) agrupados por mes
            # Para remesas, usar mes_pagado (mes siguiente al que se cobra)
            # Para otros casos, usar fecha_prevista
            cursor.execute("""
                SELECT 
                    CASE 
                        WHEN metodo_pago ILIKE 'remesa' AND mes_pagado IS NOT NULL
                        THEN mes_pagado
                        ELSE TO_CHAR(fecha_prevista, 'YYYY-MM')
                    END as mes,
                    SUM(monto) as total_previsto,
                    COUNT(*) as cantidad
                FROM pago_residente
                WHERE id_residencia = %s 
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
            """, (g.id_residencia,))
            
            estimaciones = cursor.fetchall()
            
            # Formatear datos históricos
            historico_data = []
            for row in historico:
                historico_data.append({
                    'mes': row[0],
                    'total': float(row[1]),
                    'cantidad': row[2]
                })
            
            # Formatear estimaciones
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
            query_mensual = f"""
                SELECT DISTINCT ON (p.id_residente)
                    {select_clause}
                FROM pago_residente p
                JOIN residente r ON p.id_residente = r.id_residente
                WHERE p.id_residencia = %s
                  AND p.estado = 'cobrado'
                  AND p.fecha_pago IS NOT NULL
                  AND (p.concepto ILIKE 'Pago %%' OR p.concepto ILIKE 'Pago mensual%%')
                ORDER BY p.id_residente, p.fecha_pago DESC, p.fecha_creacion DESC
            """
            
            cursor.execute(query_mensual, (g.id_residencia,))
            ultimos_mensuales = cursor.fetchall()
            
            # Obtener último pago extra de cada residente
            # Consideramos "extra" los que NO son mensuales
            query_extra = f"""
                SELECT DISTINCT ON (p.id_residente)
                    {select_clause}
                FROM pago_residente p
                JOIN residente r ON p.id_residente = r.id_residente
                WHERE p.id_residencia = %s
                  AND p.estado = 'cobrado'
                  AND p.fecha_pago IS NOT NULL
                  AND (p.concepto IS NULL OR (p.concepto NOT ILIKE 'Pago %%' AND p.concepto NOT ILIKE 'Pago mensual%%'))
                ORDER BY p.id_residente, p.fecha_pago DESC, p.fecha_creacion DESC
            """
            
            cursor.execute(query_extra, (g.id_residencia,))
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
            cursor.execute("""
                SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                       p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                       p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion
                FROM pago_residente p
                JOIN residente r ON p.id_residente = r.id_residente
                WHERE p.id_pago = %s AND p.id_residencia = %s
            """, (id_pago, g.id_residencia))
            
            cobro = cursor.fetchone()
            
            if not cobro:
                return jsonify({'error': 'Cobro no encontrado'}), 404
            
            resultado = {
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
                'fecha_creacion': cobro[12].isoformat() if cobro[12] else None
            }
            
            return jsonify(resultado), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al obtener cobro: {str(e)}")
        return jsonify({'error': 'Error al obtener cobro'}), 500


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
            # Verificar que el cobro existe y pertenece a la residencia
            cursor.execute("""
                SELECT id_pago FROM pago_residente
                WHERE id_pago = %s AND id_residencia = %s
            """, (id_pago, g.id_residencia))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Cobro no encontrado'}), 404
            
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
            
            valores.extend([id_pago, g.id_residencia])
            
            query = f"""
                UPDATE pago_residente
                SET {', '.join(updates)}
                WHERE id_pago = %s AND id_residencia = %s
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


@app.route('/api/v1/facturacion/proveedores', methods=['GET'])
def listar_pagos_proveedores():
    """Lista los pagos a proveedores de la residencia."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id_pago, proveedor, concepto, monto, fecha_pago, fecha_prevista,
                       metodo_pago, estado, numero_factura, observaciones, fecha_creacion
                FROM pago_proveedor
                WHERE id_residencia = %s
                ORDER BY COALESCE(fecha_prevista, fecha_pago) DESC
            """, (g.id_residencia,))
            
            pagos = cursor.fetchall()
            
            resultado = []
            for pago in pagos:
                resultado.append({
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
                })
            
            return jsonify({'pagos': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar pagos a proveedores: {str(e)}")
        return jsonify({'error': 'Error al obtener pagos'}), 500


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
                g.id_residencia,
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


# ============================================================================
# ENDPOINTS DE PROVEEDORES
# ============================================================================

@app.route('/api/v1/proveedores', methods=['GET'])
def listar_proveedores():
    """Lista los proveedores de la residencia del usuario."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id_proveedor, nombre, nif_cif, direccion, telefono, email,
                       contacto, tipo_servicio, activo, observaciones, fecha_creacion
                FROM proveedor
                WHERE id_residencia = %s
                ORDER BY nombre
            """, (g.id_residencia,))
            
            proveedores = cursor.fetchall()
            
            resultado = []
            for prov in proveedores:
                resultado.append({
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
                })
            
            return jsonify({'proveedores': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar proveedores: {str(e)}")
        return jsonify({'error': 'Error al obtener proveedores'}), 500


@app.route('/api/v1/proveedores', methods=['POST'])
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
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO proveedor (id_residencia, nombre, nif_cif, direccion, telefono,
                                     email, contacto, tipo_servicio, activo, observaciones)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_proveedor
            """, (
                g.id_residencia,
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
                SELECT id_proveedor, nombre, nif_cif, direccion, telefono, email,
                       contacto, tipo_servicio, activo, observaciones, fecha_creacion
                FROM proveedor
                WHERE id_proveedor = %s AND id_residencia = %s
            """, (id_proveedor, g.id_residencia))
            
            prov = cursor.fetchone()
            
            if not prov:
                return jsonify({'error': 'Proveedor no encontrado'}), 404
            
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
            # Verificar que el proveedor existe y pertenece a la residencia
            cursor.execute("""
                SELECT id_proveedor FROM proveedor
                WHERE id_proveedor = %s AND id_residencia = %s
            """, (id_proveedor, g.id_residencia))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Proveedor no encontrado'}), 404
            
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
            
            valores.extend([id_proveedor, g.id_residencia])
            
            query = f"""
                UPDATE proveedor
                SET {', '.join(updates)}
                WHERE id_proveedor = %s AND id_residencia = %s
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
            cursor.execute("""
                SELECT id_personal, nombre, apellido, documento_identidad,
                       telefono, email, cargo, activo, fecha_contratacion, fecha_creacion
                FROM personal
                WHERE id_residencia = %s
                ORDER BY apellido, nombre
            """, (g.id_residencia,))
            
            personal_list = cursor.fetchall()
            
            resultado = []
            for p in personal_list:
                resultado.append({
                    'id_personal': p[0],
                    'nombre': p[1],
                    'apellido': p[2],
                    'documento_identidad': p[3],
                    'telefono': p[4],
                    'email': p[5],
                    'cargo': p[6],
                    'activo': p[7],
                    'fecha_contratacion': str(p[8]) if p[8] else None,
                    'fecha_creacion': p[9].isoformat() if p[9] else None
                })
            
            return jsonify({'personal': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar personal: {str(e)}")
        return jsonify({'error': 'Error al obtener personal'}), 500


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
            blob_path = upload_document(
                file_content=file_content,
                id_residencia=id_residencia,
                id_residente=id_residente,
                tipo_documento=tipo_documento,
                nombre_archivo=nombre_archivo
            )
            
            if not blob_path:
                return jsonify({'error': 'Error al subir el archivo a Cloud Storage'}), 500
            
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
            app.logger.error(f"Error al crear documento: {str(e)}")
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


@app.errorhandler(404)
def not_found(error):
    """Manejo de errores 404."""
    return jsonify({'error': 'Endpoint no encontrado'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores 500."""
    return jsonify({'error': 'Error interno del servidor'}), 500


if __name__ == '__main__':
    # Para desarrollo local
    app.run(debug=True, host='0.0.0.0', port=5000)

