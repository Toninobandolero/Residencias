"""Script para verificar si la tabla proveedor existe"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()

conn = get_db_connection()
cursor = conn.cursor()

try:
    cursor.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_name = 'proveedor'
    """)
    existe = cursor.fetchone()
    if existe:
        print("✅ La tabla 'proveedor' existe")
        # Verificar columnas
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'proveedor'
            ORDER BY ordinal_position
        """)
        columnas = cursor.fetchall()
        print(f"\nColumnas ({len(columnas)}):")
        for col in columnas:
            print(f"  - {col[0]} ({col[1]})")
    else:
        print("❌ La tabla 'proveedor' NO existe")
        print("Ejecuta: python create_proveedores_table.py")
finally:
    cursor.close()
    conn.close()

