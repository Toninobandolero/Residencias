"""Script simple para actualizar esquema de facturación - versión sin bloqueos"""
import sys
from dotenv import load_dotenv

load_dotenv()

try:
    from db_connector import get_db_connection
except Exception as e:
    print(f"ERROR: No se puede importar db_connector: {e}")
    sys.exit(1)

def update_schema():
    print("Actualizando esquema de facturación...")
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Agregar campos a pago_residente
        print("Agregando campos a pago_residente...")
        try:
            cursor.execute("ALTER TABLE pago_residente ADD COLUMN IF NOT EXISTS fecha_prevista DATE")
            cursor.execute("ALTER TABLE pago_residente ADD COLUMN IF NOT EXISTS es_cobro_previsto BOOLEAN DEFAULT FALSE")
            cursor.execute("ALTER TABLE pago_residente ADD COLUMN IF NOT EXISTS observaciones TEXT")
            print("✓ Campos agregados a pago_residente")
        except Exception as e:
            print(f"⚠️  {e}")
        
        # Agregar campos a pago_proveedor
        print("Agregando campos a pago_proveedor...")
        try:
            cursor.execute("ALTER TABLE pago_proveedor ADD COLUMN IF NOT EXISTS fecha_prevista DATE")
            cursor.execute("ALTER TABLE pago_proveedor ADD COLUMN IF NOT EXISTS es_estimacion BOOLEAN DEFAULT FALSE")
            cursor.execute("ALTER TABLE pago_proveedor ADD COLUMN IF NOT EXISTS frecuencia_pago VARCHAR(50)")
            cursor.execute("ALTER TABLE pago_proveedor ADD COLUMN IF NOT EXISTS monto_estimado DECIMAL(10, 2)")
            cursor.execute("ALTER TABLE pago_proveedor ADD COLUMN IF NOT EXISTS observaciones TEXT")
            print("✓ Campos agregados a pago_proveedor")
        except Exception as e:
            print(f"⚠️  {e}")
        
        # Crear tabla historial
        print("Creando tabla historial_pago_proveedor...")
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS historial_pago_proveedor (
                    id_historial SERIAL PRIMARY KEY,
                    id_proveedor INTEGER,
                    id_residencia INTEGER NOT NULL,
                    monto DECIMAL(10, 2) NOT NULL,
                    fecha_pago DATE NOT NULL,
                    concepto TEXT,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_historial_proveedor ON historial_pago_proveedor(id_proveedor, id_residencia)")
            print("✓ Tabla historial_pago_proveedor creada")
        except Exception as e:
            print(f"⚠️  {e}")
        
        conn.commit()
        print("\n✅ Esquema actualizado correctamente")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        print("Conexión cerrada")

if __name__ == '__main__':
    try:
        update_schema()
    except KeyboardInterrupt:
        print("\n❌ Interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR FATAL: {e}")
        sys.exit(1)

