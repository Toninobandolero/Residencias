"""
Módulo para gestionar conexiones a PostgreSQL.
Lee las credenciales desde variables de entorno.
"""
import os
import psycopg2
from psycopg2 import OperationalError


def get_db_connection():
    """
    Obtiene una conexión a la base de datos PostgreSQL.
    
    Soporta tres modos:
    1. Conexión vía Unix socket (Cloud Run): Usa CLOUD_SQL_CONNECTION_NAME para construir ruta Unix socket
    2. Conexión vía Cloud SQL Proxy (DB_USE_PROXY=true): Usa 127.0.0.1 (proxy local)
    3. Conexión directa (DB_USE_PROXY=false): Usa DB_HOST directamente
    
    Variables de entorno requeridas:
    - DB_NAME: Nombre de la base de datos
    - DB_USER: Usuario de la base de datos
    - DB_PASSWORD: Contraseña de la base de datos
    - DB_HOST: Host de la base de datos (ignorado si DB_USE_PROXY=true o CLOUD_SQL_CONNECTION_NAME está definido)
    - DB_PORT: Puerto (default: 5432, ignorado si se usa Unix socket)
    - DB_USE_PROXY: 'true' para usar Cloud SQL Proxy, 'false' o no definido para conexión directa
    - CLOUD_SQL_CONNECTION_NAME: Nombre de conexión de Cloud SQL (formato: PROYECTO:REGION:INSTANCIA)
                                  Si está definido, se usa Unix socket (modo Cloud Run)
    
    Returns:
        psycopg2.connection: Objeto de conexión a PostgreSQL
        
    Raises:
        OperationalError: Si no se puede establecer la conexión
        ValueError: Si faltan variables de entorno requeridas
    """
    # Obtener variables de entorno
    cloud_sql_connection = os.getenv('CLOUD_SQL_CONNECTION_NAME')
    use_proxy = os.getenv('DB_USE_PROXY', 'false').lower() == 'true'
    
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    
    # Determinar método de conexión
    if cloud_sql_connection:
        # Modo Cloud Run: usar Unix socket
        # La ruta del socket es: /cloudsql/PROYECTO:REGION:INSTANCIA
        db_host = f'/cloudsql/{cloud_sql_connection}'
        db_port = None  # No se usa puerto con Unix socket
    elif use_proxy:
        # Modo Cloud SQL Proxy: conectar a localhost
        db_host = '127.0.0.1'
        db_port = os.getenv('DB_PORT', '5432')
    else:
        # Modo conexión directa: usar DB_HOST
        db_host = os.getenv('DB_HOST')
        db_port = os.getenv('DB_PORT', '5432')
    
    # Validar que todas las variables requeridas estén presentes
    if not all([db_host, db_name, db_user, db_password]):
        missing = []
        if not db_host and not cloud_sql_connection:
            missing.append('DB_HOST o CLOUD_SQL_CONNECTION_NAME')
        if not db_name:
            missing.append('DB_NAME')
        if not db_user:
            missing.append('DB_USER')
        if not db_password:
            missing.append('DB_PASSWORD')
        raise ValueError(f"Faltan variables de entorno requeridas: {', '.join(missing)}")
    
    try:
        # Construir parámetros de conexión
        connect_params = {
            'database': db_name,
            'user': db_user,
            'password': db_password,
            'client_encoding': 'UTF8'  # Asegurar codificación UTF-8 para caracteres especiales (ñ, acentos, etc.)
        }
        
        # Agregar host (psycopg2 detecta automáticamente Unix socket si host comienza con /)
        connect_params['host'] = db_host
        
        # Agregar port solo si no es Unix socket (Unix socket no usa puerto)
        if db_port and not cloud_sql_connection:
            connect_params['port'] = db_port
        
        # Crear conexión
        connection = psycopg2.connect(**connect_params)
        return connection
    except OperationalError as e:
        raise OperationalError(f"Error al conectar con la base de datos: {str(e)}")

