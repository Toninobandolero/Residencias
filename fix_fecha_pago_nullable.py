import sys
from dotenv import load_dotenv

load_dotenv()

try:
    from db_connector import get_db_connection
except Exception as e:
    print(f"ERROR: No se puede importar db_connector: {e}")
    sys.exit(1)

def fix_fecha_pago_nullable():
    """Permite NULL en fecha_pago para cobros previstos."""
    print("Corrigiendo restricción de fecha_pago...")
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Leer el archivo SQL
        with open('fix_fecha_pago_nullable.sql', 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        # Ejecutar cada comando SQL
        commands = sql_content.split(';')
        for command in commands:
            command = command.strip()
            if command and not command.startswith('--'):
                try:
                    cursor.execute(command)
                    print(f"✓ Ejecutado: {command[:60]}...")
                except Exception as e:
                    if 'does not exist' in str(e).lower() or 'already' in str(e).lower():
                        print(f"⚠️  {e}")
                    else:
                        print(f"❌ Error: {e}")
                        raise
        
        conn.commit()
        print("\n✅ Restricción de fecha_pago corregida correctamente!")
        print("   Ahora fecha_pago puede ser NULL para cobros previstos")
        
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    fix_fecha_pago_nullable()

