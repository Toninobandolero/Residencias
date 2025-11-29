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
from dotenv import load_dotenv
from db_connector import get_db_connection

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

@app.route('/api/v1/residentes', methods=['GET'])
def listar_residentes():
    """
    Lista todos los residentes de la residencia del usuario autenticado.
    Filtra automáticamente por id_residencia del token.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id_residente, nombre, apellido, documento_identidad, 
                       fecha_nacimiento, telefono, direccion, contacto_emergencia,
                       telefono_emergencia, activo, fecha_ingreso, habitacion,
                       costo_habitacion, servicios_extra, medicaciones, peculiaridades, fecha_creacion
                FROM residente
                WHERE id_residencia = %s
                ORDER BY apellido, nombre
            """, (g.id_residencia,))
            
            residentes = cursor.fetchall()
            
            resultado = []
            for res in residentes:
                resultado.append({
                    'id_residente': res[0],
                    'nombre': res[1],
                    'apellido': res[2],
                    'documento_identidad': res[3],
                    'fecha_nacimiento': str(res[4]) if res[4] else None,
                    'telefono': res[5],
                    'direccion': res[6],
                    'contacto_emergencia': res[7],
                    'telefono_emergencia': res[8],
                    'activo': res[9],
                    'fecha_ingreso': str(res[10]) if res[10] else None,
                    'habitacion': res[11],
                    'costo_habitacion': float(res[12]) if res[12] else None,
                    'servicios_extra': res[13],
                    'medicaciones': res[14],
                    'peculiaridades': res[15],
                    'fecha_creacion': res[16].isoformat() if res[16] else None
                })
            
            return jsonify({'residentes': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar residentes: {str(e)}")
        return jsonify({'error': 'Error al obtener residentes'}), 500


@app.route('/api/v1/residentes/<int:id_residente>', methods=['GET'])
def obtener_residente(id_residente):
    """Obtiene un residente específico (solo de la residencia del usuario)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id_residente, nombre, apellido, documento_identidad,
                       fecha_nacimiento, telefono, direccion, contacto_emergencia,
                       telefono_emergencia, activo, fecha_ingreso, habitacion,
                       costo_habitacion, servicios_extra, medicaciones, peculiaridades, fecha_creacion
                FROM residente
                WHERE id_residente = %s AND id_residencia = %s
            """, (id_residente, g.id_residencia))
            
            res = cursor.fetchone()
            
            if not res:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            return jsonify({
                'id_residente': res[0],
                'nombre': res[1],
                'apellido': res[2],
                'documento_identidad': res[3],
                'fecha_nacimiento': str(res[4]) if res[4] else None,
                'telefono': res[5],
                'direccion': res[6],
                'contacto_emergencia': res[7],
                'telefono_emergencia': res[8],
                'activo': res[9],
                'fecha_ingreso': str(res[10]) if res[10] else None,
                'habitacion': res[11],
                'costo_habitacion': float(res[12]) if res[12] else None,
                'servicios_extra': res[13],
                'medicaciones': res[14],
                'peculiaridades': res[15],
                'fecha_creacion': res[16].isoformat() if res[16] else None
            }), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al obtener residente: {str(e)}")
        return jsonify({'error': 'Error al obtener residente'}), 500


@app.route('/api/v1/residentes', methods=['POST'])
def crear_residente():
    """
    Crea un nuevo residente en la residencia del usuario autenticado.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        nombre = data.get('nombre')
        apellido = data.get('apellido')
        
        if not nombre or not apellido:
            return jsonify({'error': 'Nombre y apellido son requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO residente (id_residencia, nombre, apellido, documento_identidad,
                                     fecha_nacimiento, telefono, direccion, contacto_emergencia,
                                     telefono_emergencia, activo, fecha_ingreso, habitacion,
                                     costo_habitacion, servicios_extra, medicaciones, peculiaridades)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_residente, fecha_creacion
            """, (
                g.id_residencia,
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
                data.get('peculiaridades')
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


@app.route('/api/v1/residentes/<int:id_residente>', methods=['PUT'])
def actualizar_residente(id_residente):
    """Actualiza un residente (solo de la residencia del usuario)."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el residente existe y pertenece a la residencia
            cursor.execute("""
                SELECT id_residente FROM residente
                WHERE id_residente = %s AND id_residencia = %s
            """, (id_residente, g.id_residencia))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            # Actualizar campos permitidos
            campos_actualizables = [
                'nombre', 'apellido', 'documento_identidad', 'fecha_nacimiento',
                'telefono', 'direccion', 'contacto_emergencia', 'telefono_emergencia',
                'activo', 'fecha_ingreso', 'habitacion', 'costo_habitacion',
                'servicios_extra', 'medicaciones', 'peculiaridades'
            ]
            
            updates = []
            valores = []
            
            for campo in campos_actualizables:
                if campo in data:
                    updates.append(f"{campo} = %s")
                    valores.append(data[campo])
            
            if not updates:
                return jsonify({'error': 'No hay campos para actualizar'}), 400
            
            valores.extend([id_residente, g.id_residencia])
            
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
# ENDPOINTS DE PAGOS DE RESIDENTES
# ============================================================================

@app.route('/api/v1/pagos-residentes', methods=['GET'])
def listar_pagos_residentes():
    """Lista los pagos de residentes de la residencia del usuario."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                       p.monto, p.fecha_pago, p.mes_pagado, p.concepto,
                       p.metodo_pago, p.estado, p.fecha_creacion
                FROM pago_residente p
                JOIN residente r ON p.id_residente = r.id_residente
                WHERE p.id_residencia = %s
                ORDER BY p.fecha_pago DESC
            """, (g.id_residencia,))
            
            pagos = cursor.fetchall()
            
            resultado = []
            for pago in pagos:
                resultado.append({
                    'id_pago': pago[0],
                    'id_residente': pago[1],
                    'residente': pago[2],
                    'monto': float(pago[3]),
                    'fecha_pago': str(pago[4]),
                    'mes_pagado': pago[5],
                    'concepto': pago[6],
                    'metodo_pago': pago[7],
                    'estado': pago[8],
                    'fecha_creacion': pago[9].isoformat() if pago[9] else None
                })
            
            return jsonify({'pagos': resultado, 'total': len(resultado)}), 200
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Error al listar pagos: {str(e)}")
        return jsonify({'error': 'Error al obtener pagos'}), 500


@app.route('/api/v1/pagos-residentes', methods=['POST'])
def crear_pago_residente():
    """Crea un nuevo pago de residente."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        id_residente = data.get('id_residente')
        monto = data.get('monto')
        fecha_pago = data.get('fecha_pago')
        
        if not all([id_residente, monto, fecha_pago]):
            return jsonify({'error': 'id_residente, monto y fecha_pago son requeridos'}), 400
        
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
            
            cursor.execute("""
                INSERT INTO pago_residente (id_residente, id_residencia, monto, fecha_pago,
                                          mes_pagado, concepto, metodo_pago, estado)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_pago
            """, (
                id_residente,
                g.id_residencia,
                monto,
                fecha_pago,
                data.get('mes_pagado'),
                data.get('concepto'),
                data.get('metodo_pago'),
                data.get('estado', 'pendiente')
            ))
            
            id_pago = cursor.fetchone()[0]
            conn.commit()
            
            return jsonify({
                'id_pago': id_pago,
                'mensaje': 'Pago registrado exitosamente'
            }), 201
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error al crear pago: {str(e)}")
            return jsonify({'error': 'Error al crear pago'}), 500
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

