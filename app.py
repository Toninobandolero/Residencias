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
                SELECT r.id_residente, r.id_residencia, r.nombre, r.apellido, r.documento_identidad, 
                       r.fecha_nacimiento, r.telefono, r.direccion, r.contacto_emergencia,
                       r.telefono_emergencia, r.activo, r.fecha_ingreso, r.habitacion,
                       r.costo_habitacion, r.servicios_extra, r.medicaciones, r.peculiaridades, 
                       r.metodo_pago_preferido, r.fecha_creacion,
                       res.nombre as nombre_residencia
                FROM residente r
                JOIN residencia res ON r.id_residencia = res.id_residencia
                WHERE r.id_residencia = %s
                ORDER BY r.id_residencia, r.apellido, r.nombre
            """, (g.id_residencia,))
            
            residentes = cursor.fetchall()
            
            resultado = []
            for res in residentes:
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
                    'nombre_residencia': res[19]
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
    """Obtiene un residente específico. Permite obtener residentes de cualquier residencia para poder editarlos."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id_residente, id_residencia, nombre, apellido, documento_identidad,
                       fecha_nacimiento, telefono, direccion, contacto_emergencia,
                       telefono_emergencia, activo, fecha_ingreso, habitacion,
                       costo_habitacion, servicios_extra, medicaciones, peculiaridades, 
                       metodo_pago_preferido, fecha_creacion
                FROM residente
                WHERE id_residente = %s
            """, (id_residente,))
            
            res = cursor.fetchone()
            
            if not res:
                return jsonify({'error': 'Residente no encontrado'}), 404
            
            return jsonify({
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
                'fecha_creacion': res[18].isoformat() if res[18] else None
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
    Crea un nuevo residente. Permite elegir la residencia (Violetas 1 o Violetas 2).
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400
        
        nombre = data.get('nombre')
        apellido = data.get('apellido')
        id_residencia = data.get('id_residencia')
        
        if not nombre or not apellido:
            return jsonify({'error': 'Nombre y apellido son requeridos'}), 400
        
        # Validar que id_residencia sea 1 o 2 (Violetas 1 o Violetas 2)
        if id_residencia is None:
            return jsonify({'error': 'id_residencia es requerido'}), 400
        
        if id_residencia not in [1, 2]:
            return jsonify({'error': 'id_residencia debe ser 1 (Violetas 1) o 2 (Violetas 2)'}), 400
        
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
                                     metodo_pago_preferido)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                data.get('metodo_pago_preferido')
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
            # Si se está cambiando la residencia, validar que sea 1 o 2
            nueva_residencia = data.get('id_residencia')
            if nueva_residencia is not None:
                if nueva_residencia not in [1, 2]:
                    return jsonify({'error': 'id_residencia debe ser 1 (Violetas 1) o 2 (Violetas 2)'}), 400
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
            
            # Actualizar campos permitidos
            campos_actualizables = [
                'id_residencia', 'nombre', 'apellido', 'documento_identidad', 'fecha_nacimiento',
                'telefono', 'direccion', 'contacto_emergencia', 'telefono_emergencia',
                'activo', 'fecha_ingreso', 'habitacion', 'costo_habitacion',
                'servicios_extra', 'medicaciones', 'peculiaridades', 'metodo_pago_preferido'
            ]
            
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
            cursor.execute("""
                SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                       p.monto, p.fecha_pago, p.fecha_prevista, p.mes_pagado, p.concepto,
                       p.metodo_pago, p.estado, p.es_cobro_previsto, p.observaciones, p.fecha_creacion
                FROM pago_residente p
                JOIN residente r ON p.id_residente = r.id_residente
                WHERE p.id_residencia = %s
                ORDER BY COALESCE(p.fecha_prevista, p.fecha_pago) DESC, p.fecha_creacion DESC
            """, (g.id_residencia,))
            
            cobros = cursor.fetchall()
            
            resultado = []
            for cobro in cobros:
                resultado.append({
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
                })
            
            return jsonify({'cobros': resultado, 'total': len(resultado)}), 200
            
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
        
        id_residente = data.get('id_residente')
        monto = data.get('monto')
        fecha_prevista = data.get('fecha_prevista')
        fecha_pago = data.get('fecha_pago')
        es_cobro_previsto = data.get('es_cobro_previsto', False)
        
        if not id_residente or not monto:
            return jsonify({'error': 'id_residente y monto son requeridos'}), 400
        
        if es_cobro_previsto and not fecha_prevista:
            return jsonify({'error': 'fecha_prevista es requerida para cobros previstos'}), 400
        
        if not es_cobro_previsto and not fecha_pago:
            return jsonify({'error': 'fecha_pago es requerida para cobros realizados'}), 400
        
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
                INSERT INTO pago_residente (id_residente, id_residencia, monto, fecha_pago, fecha_prevista,
                                          mes_pagado, concepto, metodo_pago, estado, es_cobro_previsto, observaciones)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_pago
            """, (
                id_residente,
                g.id_residencia,
                monto,
                fecha_pago if not es_cobro_previsto else None,
                fecha_prevista if es_cobro_previsto else None,
                data.get('mes_pagado'),
                data.get('concepto'),
                data.get('metodo_pago'),
                data.get('estado', 'pendiente' if es_cobro_previsto else 'cobrado'),
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
    La fecha prevista se calcula según el metodo_pago_preferido:
    - transferencia: días 1-5 del mes siguiente
    - remesa: día 30 del mes siguiente
    - otros: día 5 del mes siguiente (por defecto)
    """
    try:
        data = request.get_json() or {}
        mes_referencia = data.get('mes')  # Formato: 'YYYY-MM', opcional
        año_referencia = data.get('año')  # Opcional
        
        # Si no se especifica mes, usar el mes siguiente
        if mes_referencia:
            try:
                fecha_base = datetime.strptime(f"{mes_referencia}-01", "%Y-%m-%d")
            except:
                return jsonify({'error': 'Formato de mes inválido. Use YYYY-MM'}), 400
        else:
            # Mes siguiente por defecto
            hoy = datetime.now()
            if hoy.month == 12:
                fecha_base = datetime(hoy.year + 1, 1, 1)
            else:
                fecha_base = datetime(hoy.year, hoy.month + 1, 1)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Obtener todos los residentes activos con costo_habitacion
            cursor.execute("""
                SELECT id_residente, nombre, apellido, costo_habitacion, metodo_pago_preferido
                FROM residente
                WHERE id_residencia = %s 
                  AND activo = TRUE 
                  AND costo_habitacion IS NOT NULL 
                  AND costo_habitacion > 0
            """, (g.id_residencia,))
            
            residentes = cursor.fetchall()
            
            if not residentes:
                return jsonify({
                    'mensaje': 'No hay residentes activos con costo_habitacion definido',
                    'cobros_generados': 0
                }), 200
            
            cobros_generados = 0
            cobros_duplicados = 0
            errores = []
            
            for residente in residentes:
                id_residente = residente[0]
                nombre = residente[1]
                apellido = residente[2]
                costo_habitacion = float(residente[3])
                metodo_pago = residente[4] or 'transferencia'  # Por defecto transferencia
                
                # Calcular fecha prevista según método de pago
                if metodo_pago.lower() in ['transferencia', 'transfer']:
                    # Días 1-5: usar día 3 como valor medio
                    fecha_prevista = datetime(fecha_base.year, fecha_base.month, 3)
                elif metodo_pago.lower() in ['remesa']:
                    # Día 30 del mes
                    # Calcular último día del mes
                    if fecha_base.month == 12:
                        siguiente_mes = datetime(fecha_base.year + 1, 1, 1)
                    else:
                        siguiente_mes = datetime(fecha_base.year, fecha_base.month + 1, 1)
                    ultimo_dia = (siguiente_mes - timedelta(days=1)).day
                    dia_remesa = min(30, ultimo_dia)
                    fecha_prevista = datetime(fecha_base.year, fecha_base.month, dia_remesa)
                else:
                    # Otros métodos (metálico, bizum, etc.): día 5 por defecto
                    fecha_prevista = datetime(fecha_base.year, fecha_base.month, 5)
                
                # Verificar si ya existe un cobro previsto para este residente en este mes
                mes_pagado = fecha_prevista.strftime('%Y-%m')
                cursor.execute("""
                    SELECT id_pago FROM pago_residente
                    WHERE id_residente = %s 
                      AND id_residencia = %s
                      AND es_cobro_previsto = TRUE
                      AND mes_pagado = %s
                """, (id_residente, g.id_residencia, mes_pagado))
                
                if cursor.fetchone():
                    cobros_duplicados += 1
                    continue
                
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
                        g.id_residencia,
                        costo_habitacion,
                        None,  # fecha_pago es NULL para cobros previstos
                        fecha_prevista.date(),
                        mes_pagado,
                        f"Pago mensual habitación - {nombre} {apellido}",
                        metodo_pago,
                        'pendiente',
                        True
                    ))
                    
                    cobros_generados += 1
                    
                except Exception as e:
                    errores.append(f"Error al crear cobro para {nombre} {apellido}: {str(e)}")
                    app.logger.error(f"Error al crear cobro previsto para residente {id_residente}: {str(e)}")
            
            conn.commit()
            
            resultado = {
                'mensaje': f'Cobros previstos generados exitosamente',
                'cobros_generados': cobros_generados,
                'cobros_duplicados': cobros_duplicados,
                'mes_referencia': fecha_base.strftime('%Y-%m'),
                'total_residentes_procesados': len(residentes)
            }
            
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
                       metodo_pago, estado, numero_factura, es_estimacion, frecuencia_pago,
                       monto_estimado, observaciones, fecha_creacion
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
                    'es_estimacion': pago[9],
                    'frecuencia_pago': pago[10],
                    'monto_estimado': float(pago[11]) if pago[11] else None,
                    'observaciones': pago[12],
                    'fecha_creacion': pago[13].isoformat() if pago[13] else None
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
        es_estimacion = data.get('es_estimacion', False)
        
        if not proveedor or not concepto:
            return jsonify({'error': 'proveedor y concepto son requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Si es estimación, calcular monto basado en historial si no se proporciona
            if es_estimacion and not monto:
                cursor.execute("""
                    SELECT AVG(monto) as promedio, COUNT(*) as cantidad
                    FROM historial_pago_proveedor
                    WHERE id_residencia = %s AND proveedor = %s
                """, (g.id_residencia, proveedor))
                
                hist = cursor.fetchone()
                if hist and hist[1] > 0:
                    monto = float(hist[0])
                else:
                    monto = data.get('monto_estimado', 0)
            
            if not monto or monto <= 0:
                return jsonify({'error': 'monto es requerido'}), 400
            
            cursor.execute("""
                INSERT INTO pago_proveedor (id_residencia, proveedor, concepto, monto, fecha_pago,
                                          fecha_prevista, metodo_pago, estado, numero_factura,
                                          es_estimacion, frecuencia_pago, monto_estimado, observaciones)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_pago
            """, (
                g.id_residencia,
                proveedor,
                concepto,
                monto if not es_estimacion else None,
                data.get('fecha_pago') if not es_estimacion else None,
                data.get('fecha_prevista'),
                data.get('metodo_pago'),
                data.get('estado', 'pendiente'),
                data.get('numero_factura'),
                es_estimacion,
                data.get('frecuencia_pago'),
                data.get('monto_estimado', monto) if es_estimacion else None,
                data.get('observaciones')
            ))
            
            id_pago = cursor.fetchone()[0]
            conn.commit()
            
            return jsonify({
                'id_pago': id_pago,
                'mensaje': 'Estimación creada exitosamente' if es_estimacion else 'Pago a proveedor registrado exitosamente'
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
        if not nombre:
            return jsonify({'error': 'nombre es requerido'}), 400
        
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
    """Lista los documentos de un residente."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Verificar que el residente existe y pertenece a la residencia del usuario
            cursor.execute("""
                SELECT id_residente, id_residencia FROM residente 
                WHERE id_residente = %s AND id_residencia = %s
            """, (id_residente, g.id_residencia))
            
            residente = cursor.fetchone()
            if not residente:
                return jsonify({'error': 'Residente no encontrado o no pertenece a tu residencia'}), 404
            
            cursor.execute("""
                SELECT id_documento, tipo_documento, nombre_archivo, descripcion,
                       fecha_subida, fecha_creacion, url_archivo, tamaño_bytes, tipo_mime
                FROM documento_residente
                WHERE id_residente = %s AND id_residencia = %s
                ORDER BY fecha_subida DESC
            """, (id_residente, g.id_residencia))
            
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
                # Verificar que el residente existe y pertenece a la residencia del usuario
                cursor.execute("""
                    SELECT id_residente, id_residencia FROM residente 
                    WHERE id_residente = %s AND id_residencia = %s
                """, (id_residente, g.id_residencia))
                
                residente = cursor.fetchone()
                if not residente:
                    return jsonify({'error': 'Residente no encontrado o no pertenece a tu residencia'}), 404
                
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
            # Verificar que el residente existe y pertenece a la residencia del usuario
            cursor.execute("""
                SELECT id_residente, id_residencia FROM residente 
                WHERE id_residente = %s AND id_residencia = %s
            """, (id_residente, g.id_residencia))
            
            residente = cursor.fetchone()
            if not residente:
                return jsonify({'error': 'Residente no encontrado o no pertenece a tu residencia'}), 404
            
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
            # Obtener información del documento incluyendo url_archivo y verificar residencia
            cursor.execute("""
                SELECT id_documento, url_archivo FROM documento_residente 
                WHERE id_documento = %s AND id_residencia = %s
            """, (id_documento, g.id_residencia))
            
            documento = cursor.fetchone()
            if not documento:
                return jsonify({'error': 'Documento no encontrado o no pertenece a tu residencia'}), 404
            
            url_archivo = documento[1]
            
            # Eliminar de Cloud Storage si existe
            if url_archivo:
                try:
                    delete_document(url_archivo)
                except Exception as e:
                    app.logger.warning(f"No se pudo eliminar archivo de Cloud Storage: {str(e)}")
            
            # Eliminar de base de datos (ya verificamos residencia arriba)
            cursor.execute("""
                DELETE FROM documento_residente 
                WHERE id_documento = %s AND id_residencia = %s
            """, (id_documento, g.id_residencia))
            
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
            # Verificar que el documento pertenece a la residencia del usuario
            cursor.execute("""
                SELECT url_archivo FROM documento_residente 
                WHERE id_documento = %s AND id_residencia = %s
            """, (id_documento, g.id_residencia))
            
            documento = cursor.fetchone()
            if not documento:
                return jsonify({'error': 'Documento no encontrado o no pertenece a tu residencia'}), 404
            
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

