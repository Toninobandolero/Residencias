"""Script para crear la tabla de proveedores"""
import sys
from dotenv import load_dotenv

load_dotenv()

try:
    from db_connector import get_db_connection
except Exception as e:
    print(f"ERROR: No se puede importar db_connector: {e}")
    sys.exit(1)

def create_proveedores_table():
    """Crea la tabla de proveedores."""
    print("Creando tabla de proveedores...")
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Crear tabla
        print("Creando tabla proveedor...")
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS proveedor (
                    id_proveedor SERIAL PRIMARY KEY,
                    id_residencia INTEGER NOT NULL,
                    nombre VARCHAR(255) NOT NULL,
                    nif_cif VARCHAR(50),
                    direccion TEXT,
                    telefono VARCHAR(50),
                    email VARCHAR(255),
                    contacto VARCHAR(255),
                    tipo_servicio VARCHAR(100),
                    activo BOOLEAN DEFAULT TRUE,
                    observaciones TEXT,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
                )
            """)
            conn.commit()
            print("✓ Tabla proveedor creada")
        except Exception as e:
            if 'already exists' not in str(e).lower():
                print(f"⚠️  Error al crear tabla: {e}")
                conn.rollback()
        
        # Crear índices
        print("Creando índices...")
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_proveedor_residencia ON proveedor(id_residencia)")
            conn.commit()
            print("✓ Índice idx_proveedor_residencia creado")
        except Exception as e:
            if 'already exists' not in str(e).lower():
                print(f"⚠️  Error al crear índice: {e}")
            conn.rollback()
        
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_proveedor_activo ON proveedor(activo)")
            conn.commit()
            print("✓ Índice idx_proveedor_activo creado")
        except Exception as e:
            if 'already exists' not in str(e).lower():
                print(f"⚠️  Error al crear índice: {e}")
            conn.rollback()
        print("\n✅ Tabla de proveedores creada correctamente!")
        
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
    create_proveedores_table()

