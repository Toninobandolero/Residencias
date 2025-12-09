"""
Script para crear todas las tablas de la base de datos.
"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()


def create_schema():
    """Lee y ejecuta el script SQL para crear el esquema."""
    print("\n" + "="*60)
    print("CREANDO ESQUEMA DE BASE DE DATOS")
    print("="*60)
    
    # Leer el archivo SQL
    try:
        with open('create_schema.sql', 'r', encoding='utf-8') as f:
            sql_script = f.read()
    except FileNotFoundError:
        print("❌ Error: No se encontró el archivo create_schema.sql")
        return False
    
    # Conectar a la base de datos
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("\nEjecutando script SQL...")
        
        # Ejecutar el script completo
        cursor.execute(sql_script)
        conn.commit()
        
        print("✅ Esquema creado exitosamente!")
        
        # Verificar tablas creadas
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name
        """)
        
        tables = cursor.fetchall()
        print(f"\nTablas creadas ({len(tables)}):")
        for table in tables:
            print(f"  ✓ {table[0]}")
        
        # Verificar datos iniciales
        cursor.execute("SELECT COUNT(*) FROM residencia")
        residencias = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM rol")
        roles = cursor.fetchone()[0]
        
        print(f"\nDatos iniciales:")
        print(f"  ✓ Residencias: {residencias}")
        print(f"  ✓ Roles: {roles}")
        
        cursor.close()
        conn.close()
        
        print("\n" + "="*60)
        print("✅ Base de datos lista para usar!")
        print("\nPróximos pasos:")
        print("  1. Crear un usuario: python db_utils.py create <email> <password> <id_rol> <id_residencia>")
        print("  2. Verificar estructura: python db_utils.py verify")
        print("  3. Ver información: python check_db_info.py")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error al crear el esquema: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


if __name__ == '__main__':
    create_schema()

