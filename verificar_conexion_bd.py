#!/usr/bin/env python3
import os
import sys
from dotenv import load_dotenv

if os.path.exists('.env'):
    load_dotenv()

from db_connector import get_db_connection

def verificar():
    print("=" * 60)
    print("  VERIFICACIÓN DE CONEXIÓN A BASE DE DATOS")
    print("=" * 60)
    print()
    
    db_password = os.getenv('DB_PASSWORD')
    print(f"DB_PASSWORD definido: {'✓' if db_password else '✗'}")
    if db_password:
        print(f"Longitud: {len(db_password)} caracteres")
    print()
    
    try:
        conn = get_db_connection()
        print("✅ Conexión exitosa")
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        print(f"✅ PostgreSQL conectado")
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

if __name__ == '__main__':
    verificar()
