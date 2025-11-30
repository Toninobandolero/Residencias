"""
Script de diagnóstico completo del sistema Violetas
Verifica conexión a BD, usuarios, residentes y configuración
"""
import os
import sys
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

print("=" * 60)
print("🔍 DIAGNÓSTICO DEL SISTEMA VIOLETAS")
print("=" * 60)
print()

# 1. Verificar variables de entorno
print("1️⃣ VERIFICANDO VARIABLES DE ENTORNO")
print("-" * 60)
env_vars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'JWT_SECRET_KEY']
missing = []
for var in env_vars:
    value = os.getenv(var)
    if value:
        # Ocultar contraseñas
        if 'PASSWORD' in var or 'SECRET' in var:
            print(f"  ✅ {var}: {'*' * 20}")
        else:
            print(f"  ✅ {var}: {value}")
    else:
        print(f"  ❌ {var}: NO DEFINIDA")
        missing.append(var)

if missing:
    print(f"\n⚠️  Faltan variables: {', '.join(missing)}")
    print("   Asegúrate de tener un archivo .env con todas las variables")
    sys.exit(1)

print()

# 2. Verificar conexión a BD
print("2️⃣ VERIFICANDO CONEXIÓN A BASE DE DATOS")
print("-" * 60)
try:
    from db_connector import get_db_connection
    conn = get_db_connection()
    print("  ✅ Conexión a base de datos exitosa")
    cursor = conn.cursor()
    
    # Verificar tablas
    cursor.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        ORDER BY table_name
    """)
    tables = [row[0] for row in cursor.fetchall()]
    print(f"  ✅ Tablas encontradas: {len(tables)}")
    print(f"     {', '.join(tables[:5])}{'...' if len(tables) > 5 else ''}")
    
    # Verificar usuarios
    cursor.execute("SELECT COUNT(*) FROM usuario")
    user_count = cursor.fetchone()[0]
    print(f"  ✅ Usuarios en BD: {user_count}")
    
    if user_count > 0:
        cursor.execute("SELECT email, id_residencia, id_rol FROM usuario LIMIT 5")
        users = cursor.fetchall()
        print("     Usuarios:")
        for u in users:
            print(f"       - {u[0]} (Residencia: {u[1]}, Rol: {u[2]})")
    
    # Verificar residentes
    cursor.execute("SELECT COUNT(*) FROM residente")
    res_count = cursor.fetchone()[0]
    print(f"  ✅ Residentes en BD: {res_count}")
    
    if res_count > 0:
        cursor.execute("""
            SELECT id_residente, nombre, apellido, id_residencia, activo 
            FROM residente 
            ORDER BY id_residencia, apellido 
            LIMIT 10
        """)
        residents = cursor.fetchall()
        print("     Residentes:")
        for r in residents:
            estado = "✅ Activo" if r[4] else "❌ Inactivo"
            print(f"       - {r[1]} {r[2]} (Residencia: {r[3]}) {estado}")
    
    # Verificar residencias
    cursor.execute("SELECT id_residencia, nombre FROM residencia")
    residencias = cursor.fetchall()
    print(f"  ✅ Residencias configuradas: {len(residencias)}")
    for r in residencias:
        print(f"       - {r[1]} (ID: {r[0]})")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"  ❌ Error al conectar: {str(e)}")
    print(f"     Tipo: {type(e).__name__}")
    sys.exit(1)

print()

# 3. Verificar configuración del servidor
print("3️⃣ VERIFICANDO CONFIGURACIÓN DEL SERVIDOR")
print("-" * 60)
try:
    # Verificar que app.py existe
    if os.path.exists('app.py'):
        print("  ✅ app.py encontrado")
    else:
        print("  ❌ app.py NO encontrado")
    
    # Verificar que static/index.html existe
    if os.path.exists('static/index.html'):
        print("  ✅ static/index.html encontrado")
    else:
        print("  ❌ static/index.html NO encontrado")
    
    # Verificar puerto
    print("  ℹ️  Puerto configurado: 5000")
    print("  ℹ️  Host configurado: 0.0.0.0 (todas las interfaces)")
    
except Exception as e:
    print(f"  ❌ Error: {str(e)}")

print()

# 4. Resumen y recomendaciones
print("4️⃣ RESUMEN Y RECOMENDACIONES")
print("-" * 60)

if res_count == 0:
    print("  ⚠️  NO HAY RESIDENTES EN LA BASE DE DATOS")
    print("     Solución: Crear residentes desde el frontend o insertar directamente")
    print()
    
if user_count == 0:
    print("  ⚠️  NO HAY USUARIOS EN LA BASE DE DATOS")
    print("     Solución: Crear usuario con db_utils.py")
    print()

print("  ✅ Para iniciar el servidor:")
print("     python app.py")
print("     o")
print("     .\\start_server.ps1")
print()
print("  ✅ Para acceder al sistema:")
print("     http://localhost:5000")
print()
print("  ✅ Credenciales de prueba (si existen):")
print("     Email: admin@violetas1.com")
print("     Password: admin123")
print()

print("=" * 60)
print("✅ DIAGNÓSTICO COMPLETADO")
print("=" * 60)

