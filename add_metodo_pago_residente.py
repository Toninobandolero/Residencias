"""
Script para añadir el campo metodo_pago_preferido a la tabla residente.
"""
import sys
from dotenv import load_dotenv

load_dotenv()

try:
    from db_connector import get_db_connection
except Exception as e:
    print(f"ERROR: No se puede importar db_connector: {e}")
    sys.exit(1)

def add_metodo_pago_preferido():
    """Añade el campo metodo_pago_preferido a la tabla residente."""
    print("Añadiendo campo metodo_pago_preferido a la tabla residente...")
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Leer el archivo SQL
        with open('add_metodo_pago_residente.sql', 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        # Ejecutar cada comando SQL
        commands = sql_content.split(';')
        for command in commands:
            command = command.strip()
            if command and not command.startswith('--'):
                try:
                    cursor.execute(command)
                    print(f"✓ Ejecutado: {command[:50]}...")
                except Exception as e:
                    # Ignorar errores de "ya existe"
                    if 'already exists' in str(e).lower() or 'duplicate' in str(e).lower():
                        print(f"⚠️  Campo ya existe: {command[:50]}...")
                    else:
                        print(f"⚠️  {e}")
        
        conn.commit()
        print("\n✅ Campo metodo_pago_preferido añadido correctamente!")
        
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
    add_metodo_pago_preferido()

