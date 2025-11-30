"""
Script para probar la conexión a la base de datos y leer datos
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()

print("=" * 60)
print("🔍 PRUEBA DE CONEXIÓN Y LECTURA DE BASE DE DATOS")
print("=" * 60)
print()

try:
    from db_connector import get_db_connection
    
    print("1️⃣ Intentando conectar a la base de datos...")
    conn = get_db_connection()
    print("   ✅ Conexión exitosa!")
    print()
    
    cursor = conn.cursor()
    
    # Verificar tablas
    print("2️⃣ Verificando tablas...")
    cursor.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        ORDER BY table_name
    """)
    tables = [row[0] for row in cursor.fetchall()]
    print(f"   ✅ Tablas encontradas: {len(tables)}")
    for table in tables[:10]:
        print(f"      - {table}")
    print()
    
    # Verificar usuarios
    print("3️⃣ Leyendo usuarios...")
    try:
        cursor.execute("SELECT COUNT(*) FROM usuario")
        user_count = cursor.fetchone()[0]
        print(f"   ✅ Total usuarios: {user_count}")
        
        if user_count > 0:
            cursor.execute("SELECT id_usuario, email, id_residencia, id_rol FROM usuario LIMIT 5")
            users = cursor.fetchall()
            print("   Usuarios encontrados:")
            for u in users:
                print(f"      - ID: {u[0]}, Email: {u[1]}, Residencia: {u[2]}, Rol: {u[3]}")
        else:
            print("   ⚠️  No hay usuarios en la base de datos")
    except Exception as e:
        print(f"   ❌ Error al leer usuarios: {str(e)}")
    print()
    
    # Verificar residentes
    print("4️⃣ Leyendo residentes...")
    try:
        cursor.execute("SELECT COUNT(*) FROM residente")
        res_count = cursor.fetchone()[0]
        print(f"   ✅ Total residentes: {res_count}")
        
        if res_count > 0:
            cursor.execute("""
                SELECT id_residente, nombre, apellido, id_residencia, activo 
                FROM residente 
                ORDER BY id_residencia, apellido 
                LIMIT 10
            """)
            residents = cursor.fetchall()
            print("   Residentes encontrados:")
            for r in residents:
                estado = "✅ Activo" if r[4] else "❌ Inactivo"
                print(f"      - {r[1]} {r[2]} (Residencia: {r[3]}) {estado}")
        else:
            print("   ⚠️  No hay residentes en la base de datos")
            print("   💡 Esto es normal si es la primera vez. Crea residentes desde el frontend.")
    except Exception as e:
        print(f"   ❌ Error al leer residentes: {str(e)}")
    print()
    
    # Verificar residencias
    print("5️⃣ Verificando residencias...")
    try:
        cursor.execute("SELECT id_residencia, nombre FROM residencia")
        residencias = cursor.fetchall()
        print(f"   ✅ Residencias configuradas: {len(residencias)}")
        for r in residencias:
            print(f"      - {r[1]} (ID: {r[0]})")
    except Exception as e:
        print(f"   ❌ Error al leer residencias: {str(e)}")
    print()
    
    # Probar consulta específica como lo hace el endpoint
    print("6️⃣ Probando consulta del endpoint de residentes...")
    try:
        # Simular consulta con id_residencia = 1
        cursor.execute("""
            SELECT r.id_residente, r.id_residencia, r.nombre, r.apellido, 
                   r.documento_identidad, r.fecha_nacimiento, r.telefono, 
                   r.direccion, r.contacto_emergencia, r.telefono_emergencia, 
                   r.activo, r.fecha_ingreso, r.habitacion,
                   r.costo_habitacion, r.servicios_extra, r.medicaciones, 
                   r.peculiaridades, r.metodo_pago_preferido, r.fecha_creacion,
                   res.nombre as nombre_residencia
            FROM residente r
            JOIN residencia res ON r.id_residencia = res.id_residencia
            WHERE r.id_residencia = %s
            ORDER BY r.id_residencia, r.apellido, r.nombre
        """, (1,))
        
        residentes = cursor.fetchall()
        print(f"   ✅ Consulta exitosa. Residentes en residencia 1: {len(residentes)}")
        
        if len(residentes) > 0:
            print("   Primeros resultados:")
            for r in residentes[:3]:
                print(f"      - {r[2]} {r[3]} (ID: {r[0]})")
    except Exception as e:
        print(f"   ❌ Error en la consulta: {str(e)}")
        import traceback
        traceback.print_exc()
    print()
    
    cursor.close()
    conn.close()
    print("=" * 60)
    print("✅ PRUEBA COMPLETADA")
    print("=" * 60)
    
except Exception as e:
    print(f"❌ ERROR: {str(e)}")
    print()
    print("Posibles causas:")
    print("1. La IP no está autorizada en Cloud SQL")
    print("2. Error de conexión a la base de datos")
    print("3. Variables de entorno incorrectas")
    print()
    print("Solución:")
    print("1. Ejecuta: python obtener_mi_ip.py")
    print("2. Autoriza tu IP en Cloud SQL")
    print("3. Espera 1-2 minutos y vuelve a intentar")
    sys.exit(1)

