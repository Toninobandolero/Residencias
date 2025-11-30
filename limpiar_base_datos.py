"""
Script para limpiar todos los datos de la base de datos.
ADVERTENCIA: Este script eliminará TODOS los registros de todas las tablas.
"""

import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Cargar variables de entorno
load_dotenv()

def limpiar_base_datos():
    """Elimina todos los datos de la base de datos manteniendo la estructura."""
    
    # Obtener credenciales de la base de datos
    db_host = os.getenv('DB_HOST', 'localhost')
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_port = os.getenv('DB_PORT', '5432')
    
    if not all([db_name, db_user, db_password]):
        print("❌ Error: Faltan variables de entorno requeridas (DB_NAME, DB_USER, DB_PASSWORD)")
        sys.exit(1)
    
    try:
        # Conectar a la base de datos
        print(f"🔌 Conectando a la base de datos {db_name} en {db_host}...")
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        print("⚠️  ADVERTENCIA: Este script eliminará TODOS los datos de la base de datos.")
        respuesta = input("¿Estás seguro de que quieres continuar? (escribe 'SI' para confirmar): ")
        
        if respuesta != 'SI':
            print("❌ Operación cancelada.")
            cursor.close()
            conn.close()
            return
        
        print("\n🗑️  Eliminando datos...")
        
        # Eliminar datos en orden inverso de dependencias (respetando foreign keys)
        tablas = [
            ('documento_residente', 'documento_residente_id_documento_seq'),
            ('pago_residente', 'pago_residente_id_pago_seq'),
            ('pago_proveedor', 'pago_proveedor_id_pago_seq'),
            ('proveedor', 'proveedor_id_proveedor_seq'),
            ('residente', 'residente_id_residente_seq'),
        ]
        
        for tabla, secuencia in tablas:
            try:
                # Contar registros antes de eliminar
                cursor.execute(f"SELECT COUNT(*) FROM {tabla};")
                count = cursor.fetchone()[0]
                
                if count > 0:
                    cursor.execute(f"DELETE FROM {tabla};")
                    print(f"  ✓ Eliminados {count} registros de {tabla}")
                else:
                    print(f"  - {tabla} ya estaba vacía")
                
                # Resetear secuencia
                try:
                    cursor.execute(f"ALTER SEQUENCE IF EXISTS {secuencia} RESTART WITH 1;")
                except Exception as e:
                    print(f"  ⚠ No se pudo resetear la secuencia {secuencia}: {e}")
                    
            except Exception as e:
                print(f"  ⚠ Error al limpiar {tabla}: {e}")
        
        # NO eliminar usuarios - mantener todos los usuarios del sistema
        print("  ✓ Usuarios preservados (incluyendo administradores)")
        
        # Verificar que las tablas están vacías (excepto usuarios y residencias)
        print("\n📊 Verificando estado de las tablas:")
        cursor.execute("""
            SELECT 
                'documento_residente' as tabla, COUNT(*) as registros FROM documento_residente
            UNION ALL
            SELECT 'pago_residente', COUNT(*) FROM pago_residente
            UNION ALL
            SELECT 'pago_proveedor', COUNT(*) FROM pago_proveedor
            UNION ALL
            SELECT 'proveedor', COUNT(*) FROM proveedor
            UNION ALL
            SELECT 'residente', COUNT(*) FROM residente
            UNION ALL
            SELECT 'usuario', COUNT(*) FROM usuario
            UNION ALL
            SELECT 'residencia', COUNT(*) FROM residencia
            ORDER BY tabla;
        """)
        
        resultados = cursor.fetchall()
        for tabla, registros in resultados:
            if tabla in ['usuario', 'residencia']:
                # Estas tablas deben tener registros (usuarios y residencias se mantienen)
                status = "✓" if registros > 0 else "⚠"
                print(f"  {status} {tabla}: {registros} registros (preservados)")
            else:
                # Estas tablas deben estar vacías
                status = "✓" if registros == 0 else "⚠"
                print(f"  {status} {tabla}: {registros} registros")
        
        print("\n✅ Limpieza completada exitosamente.")
        print("💡 La estructura de las tablas se ha mantenido intacta.")
        print("💡 Los usuarios y residencias se han preservado.")
        print("💡 Puedes empezar a agregar nuevos datos desde cero.")
        
        cursor.close()
        conn.close()
        
    except psycopg2.Error as e:
        print(f"❌ Error de base de datos: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    limpiar_base_datos()

