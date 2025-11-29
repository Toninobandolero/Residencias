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
    
    Variables de entorno requeridas:
    - DB_HOST: Host de la base de datos (Cloud SQL endpoint)
    - DB_NAME: Nombre de la base de datos
    - DB_USER: Usuario de la base de datos
    - DB_PASSWORD: Contraseña de la base de datos
    - DB_PORT: Puerto (default: 5432)
    
    Returns:
        psycopg2.connection: Objeto de conexión a PostgreSQL
        
    Raises:
        OperationalError: Si no se puede establecer la conexión
        ValueError: Si faltan variables de entorno requeridas
    """
    # Obtener variables de entorno
    db_host = os.getenv('DB_HOST')
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_port = os.getenv('DB_PORT', '5432')
    
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
        # Crear conexión
        connection = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port
        )
        return connection
    except OperationalError as e:
        raise OperationalError(f"Error al conectar con la base de datos: {str(e)}")

