"""
Script para crear la tabla unificada de documentación.
"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()


def create_documentos_unificado():
    """Crea la tabla unificada de documentación."""
    print("\n" + "="*60)
    print("CREANDO TABLA UNIFICADA DE DOCUMENTACIÓN")
    print("="*60)
    
    try:
        with open('create_documentos_unificado.sql', 'r', encoding='utf-8') as f:
            sql_script = f.read()
    except FileNotFoundError:
        print("❌ Error: No se encontró el archivo create_documentos_unificado.sql")
        return False
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("\nEjecutando script SQL...")
        cursor.execute(sql_script)
        conn.commit()
        
        print("✅ Tabla de documentación unificada creada exitosamente!")
        
        # Verificar que la tabla existe
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'documento'
            ORDER BY ordinal_position
        """)
        
        campos = cursor.fetchall()
        print(f"\nCampos de la tabla ({len(campos)}):")
        for campo in campos:
            print(f"  ✓ {campo[0]} ({campo[1]})")
        
        cursor.close()
        conn.close()
        
        print("\n" + "="*60)
        print("✅ Base de datos actualizada!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error al crear la tabla: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


if __name__ == '__main__':
    create_documentos_unificado()

