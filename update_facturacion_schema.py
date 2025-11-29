"""
Script para actualizar el esquema de base de datos para Facturación.
"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()


def update_facturacion_schema():
    """Actualiza el esquema para el módulo de Facturación."""
    print("\n" + "="*60)
    print("ACTUALIZANDO ESQUEMA PARA FACTURACIÓN")
    print("="*60)
    
    try:
        with open('update_facturacion_schema.sql', 'r', encoding='utf-8') as f:
            sql_script = f.read()
    except FileNotFoundError:
        print("❌ Error: No se encontró el archivo update_facturacion_schema.sql")
        return False
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("\nEjecutando script SQL...")
        # Ejecutar cada comando por separado
        commands = sql_script.split(';')
        for cmd in commands:
            cmd = cmd.strip()
            if cmd and not cmd.startswith('--'):
                try:
                    cursor.execute(cmd)
                except Exception as e:
                    # Ignorar errores de "ya existe"
                    if 'already exists' not in str(e).lower() and 'duplicate' not in str(e).lower():
                        print(f"⚠️  Advertencia: {str(e)}")
        
        conn.commit()
        
        print("✅ Esquema actualizado exitosamente!")
        
        # Verificar cambios
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'pago_residente' 
            AND column_name IN ('fecha_prevista', 'es_cobro_previsto', 'observaciones')
        """)
        campos_cobros = cursor.fetchall()
        print(f"\nCampos agregados a pago_residente ({len(campos_cobros)}):")
        for campo in campos_cobros:
            print(f"  ✓ {campo[0]}")
        
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'pago_proveedor' 
            AND column_name IN ('fecha_prevista', 'es_estimacion', 'frecuencia_pago', 'monto_estimado', 'observaciones')
        """)
        campos_proveedores = cursor.fetchall()
        print(f"\nCampos agregados a pago_proveedor ({len(campos_proveedores)}):")
        for campo in campos_proveedores:
            print(f"  ✓ {campo[0]}")
        
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_name = 'historial_pago_proveedor'
        """)
        if cursor.fetchone():
            print("\n✅ Tabla historial_pago_proveedor creada")
        
        cursor.close()
        conn.close()
        
        print("\n" + "="*60)
        print("✅ Base de datos actualizada!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error al actualizar el esquema: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


if __name__ == '__main__':
    update_facturacion_schema()

