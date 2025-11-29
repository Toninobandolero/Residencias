"""Script directo para añadir el campo metodo_pago_preferido"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()

print("Añadiendo campo metodo_pago_preferido...")

try:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Añadir el campo directamente
    try:
        cursor.execute("""
            ALTER TABLE residente
            ADD COLUMN IF NOT EXISTS metodo_pago_preferido VARCHAR(50)
        """)
        conn.commit()
        print("✅ Campo añadido correctamente")
    except Exception as e:
        print(f"⚠️  Error al añadir campo: {str(e)}")
        conn.rollback()
    
    # Verificar que se añadió
    cursor.execute("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'residente' 
        AND column_name = 'metodo_pago_preferido'
    """)
    
    existe = cursor.fetchone()
    if existe:
        print("✅ Verificación: El campo existe en la base de datos")
    else:
        print("❌ Verificación: El campo NO existe después de intentar añadirlo")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {str(e)}")

