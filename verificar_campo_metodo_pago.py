"""Script para verificar si el campo metodo_pago_preferido existe en la tabla residente"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()

try:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar si el campo existe
    cursor.execute("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'residente' 
        AND column_name = 'metodo_pago_preferido'
    """)
    
    existe = cursor.fetchone()
    
    if existe:
        print("✅ El campo 'metodo_pago_preferido' existe en la tabla residente")
    else:
        print("❌ El campo 'metodo_pago_preferido' NO existe en la tabla residente")
        print("   Ejecuta: python add_metodo_pago_residente.py")
    
    # Listar todas las columnas de la tabla residente
    cursor.execute("""
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'residente'
        ORDER BY ordinal_position
    """)
    
    columnas = cursor.fetchall()
    print(f"\nColumnas de la tabla residente ({len(columnas)}):")
    for col in columnas:
        print(f"  - {col[0]} ({col[1]})")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {str(e)}")

