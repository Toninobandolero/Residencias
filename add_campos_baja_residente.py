#!/usr/bin/env python3
"""
Script para añadir campos de baja a la tabla residente.
Ejecuta el script SQL add_campos_baja_residente.sql
"""

import os
import sys
from dotenv import load_dotenv
from db_connector import get_db_connection

def add_campos_baja():
    """Añade campos de baja a la tabla residente."""
    try:
        # Cargar variables de entorno
        load_dotenv()
        
        # Leer el script SQL
        script_path = os.path.join(os.path.dirname(__file__), 'add_campos_baja_residente.sql')
        with open(script_path, 'r', encoding='utf-8') as f:
            sql_script = f.read()
        
        # Conectar a la base de datos
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Ejecutar el script SQL
            cursor.execute(sql_script)
            conn.commit()
            
            print("✅ Campos de baja añadidos exitosamente a la tabla residente:")
            print("   - motivo_baja")
            print("   - fecha_baja")
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Error al ejecutar el script SQL: {str(e)}")
            sys.exit(1)
        finally:
            cursor.close()
            conn.close()
            
    except FileNotFoundError:
        print(f"❌ Error: No se encontró el archivo add_campos_baja_residente.sql")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    add_campos_baja()

