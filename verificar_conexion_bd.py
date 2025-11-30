"""
Script para verificar la conexión a la base de datos.
"""
import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2 import OperationalError

load_dotenv()

def verificar_conexion():
    """Verifica la conexión a la base de datos."""
    print("🔍 Verificando conexión a la base de datos...")
    print("=" * 60)
    
    db_host = os.getenv('DB_HOST')
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_port = os.getenv('DB_PORT', '5432')
    
    print(f"📋 Variables de entorno:")
    print(f"   DB_HOST: {db_host if db_host else '❌ NO DEFINIDA'}")
    print(f"   DB_NAME: {db_name if db_name else '❌ NO DEFINIDA'}")
    print(f"   DB_USER: {db_user if db_user else '❌ NO DEFINIDA'}")
    print(f"   DB_PASSWORD: {'✅ DEFINIDA' if db_password else '❌ NO DEFINIDA'}")
    print(f"   DB_PORT: {db_port}")
    print()
    
    if not all([db_host, db_name, db_user, db_password]):
        print("❌ Error: Faltan variables de entorno requeridas")
        print("   Verifica que el archivo .env exista y contenga todas las variables necesarias")
        return False
    
    print("🔌 Intentando conectar a la base de datos...")
    conn = None
    cursor = None
    try:
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port,
            connect_timeout=10
        )
        print("✅ Conexión exitosa a la base de datos\n")
        
        cursor = conn.cursor()
        
        # Verificar versión de PostgreSQL
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print(f"📊 Versión de PostgreSQL: {version.split(',')[0]}\n")
        
        # Verificar que las tablas necesarias existan
        print("📋 Verificando tablas necesarias...")
        tablas_requeridas = ['residente', 'pago_residente', 'residencia']
        
        for tabla in tablas_requeridas:
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = %s
                );
            """, (tabla,))
            existe = cursor.fetchone()[0]
            if existe:
                print(f"   ✅ Tabla '{tabla}' existe")
            else:
                print(f"   ❌ Tabla '{tabla}' NO existe")
        
        print()
        
        # Contar residentes
        cursor.execute("SELECT COUNT(*) FROM residente;")
        total_residentes = cursor.fetchone()[0]
        print(f"👥 Total de residentes en BD: {total_residentes}")
        
        cursor.execute("SELECT COUNT(*) FROM residente WHERE activo = TRUE;")
        residentes_activos = cursor.fetchone()[0]
        print(f"   ✅ Residentes activos: {residentes_activos}")
        print(f"   ❌ Residentes inactivos: {total_residentes - residentes_activos}")
        print()
        
        # Contar cobros previstos
        cursor.execute("""
            SELECT COUNT(*) FROM pago_residente 
            WHERE es_cobro_previsto = TRUE AND estado = 'pendiente';
        """)
        cobros_previstos = cursor.fetchone()[0]
        print(f"💰 Cobros previstos pendientes: {cobros_previstos}")
        
        # Verificar uso de proxy
        use_proxy = os.getenv('DB_USE_PROXY', 'false').lower() == 'true'
        if use_proxy:
            print(f"\n🔐 Cloud SQL Proxy: ACTIVADO")
            cloud_sql_conn = os.getenv('CLOUD_SQL_CONNECTION_NAME')
            if cloud_sql_conn:
                print(f"   Connection name: {cloud_sql_conn}")
            else:
                print(f"   ⚠️  CLOUD_SQL_CONNECTION_NAME no definida")
        else:
            print(f"\n🔐 Cloud SQL Proxy: DESACTIVADO (conexión directa)")
        
        print("\n✅ Verificación completada exitosamente")
        return True
        
    except OperationalError as e:
        print(f"\n❌ Error de conexión: {str(e)}")
        print("\nPosibles causas:")
        print("   1. El servidor de base de datos no está corriendo")
        print("   2. Las credenciales son incorrectas")
        print("   3. El host/puerto no es accesible")
        print("   4. Si usas Cloud SQL Proxy, verifica que esté corriendo")
        return False
    except Exception as e:
        print(f"\n❌ Error inesperado: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    exito = verificar_conexion()
    sys.exit(0 if exito else 1)

