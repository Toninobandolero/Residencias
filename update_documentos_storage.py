"""
Script para actualizar la tabla de documentos con campos de Cloud Storage.
"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()


def update_documentos_table():
    """Actualiza la tabla de documentos con campos de almacenamiento."""
    print("\n" + "="*60)
    print("ACTUALIZANDO TABLA DE DOCUMENTOS PARA CLOUD STORAGE")
    print("="*60)
    
    try:
        with open('update_documentos_table_storage.sql', 'r', encoding='utf-8') as f:
            sql_script = f.read()
    except FileNotFoundError:
        print("❌ Error: No se encontró el archivo update_documentos_table_storage.sql")
        return False
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("\nEjecutando script SQL...")
        cursor.execute(sql_script)
        conn.commit()
        
        print("✅ Tabla actualizada exitosamente!")
        
        # Verificar que los campos existen
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'documento_residente' 
            AND column_name IN ('url_archivo', 'tamaño_bytes', 'tipo_mime')
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
        print(f"\n❌ Error al actualizar la tabla: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


if __name__ == '__main__':
    update_documentos_table()

