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
    
    Soporta dos modos:
    1. Conexión directa (DB_USE_PROXY=false o no definido): Usa DB_HOST directamente
    2. Conexión vía Cloud SQL Proxy (DB_USE_PROXY=true): Usa 127.0.0.1 (proxy local)
    
    Variables de entorno requeridas:
    - DB_NAME: Nombre de la base de datos
    - DB_USER: Usuario de la base de datos
    - DB_PASSWORD: Contraseña de la base de datos
    - DB_HOST: Host de la base de datos (ignorado si DB_USE_PROXY=true)
    - DB_PORT: Puerto (default: 5432)
    - DB_USE_PROXY: 'true' para usar Cloud SQL Proxy, 'false' o no definido para conexión directa
    
    Returns:
        psycopg2.connection: Objeto de conexión a PostgreSQL
        
    Raises:
        OperationalError: Si no se puede establecer la conexión
        ValueError: Si faltan variables de entorno requeridas
    """
    # Obtener variables de entorno
    use_proxy = os.getenv('DB_USE_PROXY', 'false').lower() == 'true'
    
    # Si se usa proxy, siempre conectar a localhost
    if use_proxy:
        db_host = '127.0.0.1'
        db_port = os.getenv('DB_PORT', '5432')
    else:
        db_host = os.getenv('DB_HOST')
        db_port = os.getenv('DB_PORT', '5432')
    
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    
    # Validar que todas las variables requeridas estén presentes
    if not all([db_host, db_name, db_user, db_password]):
        missing = []
        if not db_host:
            missing.append('DB_HOST')
        if not db_name:
            missing.append('DB_NAME')
        if not db_user:
            missing.append('DB_USER')
        if not db_password:
            missing.append('DB_PASSWORD')
        raise ValueError(f"Faltan variables de entorno requeridas: {', '.join(missing)}")
    
    try:
        # Crear conexión con codificación UTF-8 explícita
        connection = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port,
            client_encoding='UTF8'  # Asegurar codificación UTF-8 para caracteres especiales (ñ, acentos, etc.)
        )
        return connection
    except OperationalError as e:
        raise OperationalError(f"Error al conectar con la base de datos: {str(e)}")

