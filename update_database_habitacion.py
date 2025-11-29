"""
Script para agregar el campo habitacion a la tabla residente.
"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()


def add_habitacion_field():
    """Agrega el campo habitacion a la tabla residente."""
    print("\n" + "="*60)
    print("AGREGANDO CAMPO HABITACIÓN A LA TABLA RESIDENTE")
    print("="*60)
    
    try:
        with open('add_habitacion_field.sql', 'r', encoding='utf-8') as f:
            sql_script = f.read()
    except FileNotFoundError:
        print("❌ Error: No se encontró el archivo add_habitacion_field.sql")
        return False
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("\nEjecutando script SQL...")
        cursor.execute(sql_script)
        conn.commit()
        
        print("✅ Campo 'habitacion' agregado exitosamente!")
        
        # Verificar que el campo existe
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'residente' AND column_name = 'habitacion'
        """)
        
        if cursor.fetchone():
            print("✅ Verificación: Campo 'habitacion' existe en la tabla residente")
        else:
            print("⚠️  Advertencia: No se pudo verificar el campo")
        
        cursor.close()
        conn.close()
        
        print("\n" + "="*60)
        print("✅ Base de datos actualizada!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error al actualizar la base de datos: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


if __name__ == '__main__':
    add_habitacion_field()

