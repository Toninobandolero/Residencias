#!/usr/bin/env python3
"""
Script para ejecutar el SQL de creación de la tabla receiver y relación con residencias.
"""

import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2 import sql

# Cargar variables de entorno
load_dotenv()

def ejecutar_sql():
    """Ejecuta el script SQL para crear la tabla receiver."""
    
    # Leer el archivo SQL
    sql_file = 'add_receiver_table.sql'
    
    if not os.path.exists(sql_file):
        print(f"Error: No se encontró el archivo {sql_file}")
        sys.exit(1)
    
    with open(sql_file, 'r', encoding='utf-8') as f:
        sql_content = f.read()
    
    # Conectar a la base de datos
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST'),
            port=os.getenv('DB_PORT', 5432),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD')
        )
        
        cursor = conn.cursor()
        
        # Ejecutar el SQL
        print("Ejecutando script SQL...")
        cursor.execute(sql_content)
        conn.commit()
        
        print("✅ Tabla receiver y relación residencia_receiver creadas exitosamente")
        print("✅ Columna id_receiver añadida a pago_proveedor")
        
        cursor.close()
        conn.close()
        
    except psycopg2.Error as e:
        print(f"Error al ejecutar SQL: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error inesperado: {e}")
        sys.exit(1)

if __name__ == '__main__':
    ejecutar_sql()

