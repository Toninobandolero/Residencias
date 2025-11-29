"""
Script para agregar campos adicionales a la tabla residente.
"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()


def add_campos_extra():
    """Agrega campos adicionales a la tabla residente."""
    print("\n" + "="*60)
    print("AGREGANDO CAMPOS ADICIONALES A LA TABLA RESIDENTE")
    print("="*60)
    
    try:
        with open('add_residente_campos_extra.sql', 'r', encoding='utf-8') as f:
            sql_script = f.read()
    except FileNotFoundError:
        print("❌ Error: No se encontró el archivo add_residente_campos_extra.sql")
        return False
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("\nEjecutando script SQL...")
        cursor.execute(sql_script)
        conn.commit()
        
        print("✅ Campos adicionales agregados exitosamente!")
        
        # Verificar que los campos existen
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'residente' 
            AND column_name IN ('costo_habitacion', 'servicios_extra', 'medicaciones', 'peculiaridades')
            ORDER BY column_name
        """)
        
        campos = cursor.fetchall()
        print(f"\nCampos agregados ({len(campos)}):")
        for campo in campos:
            print(f"  ✓ {campo[0]} ({campo[1]})")
        
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
    add_campos_extra()

