"""Script de diagnóstico para identificar problemas"""
import sys
import traceback

print("=== DIAGNÓSTICO ===")
print("1. Verificando imports...")

try:
    from dotenv import load_dotenv
    print("✓ dotenv OK")
except Exception as e:
    print(f"✗ dotenv ERROR: {e}")
    sys.exit(1)

try:
    load_dotenv()
    print("✓ load_dotenv OK")
except Exception as e:
    print(f"✗ load_dotenv ERROR: {e}")

print("\n2. Verificando conexión a BD...")
try:
    from db_connector import get_db_connection
    print("✓ db_connector importado")
    
    conn = get_db_connection()
    print("✓ Conexión establecida")
    
    cursor = conn.cursor()
    cursor.execute("SELECT 1")
    cursor.fetchone()
    print("✓ Query de prueba OK")
    
    cursor.close()
    conn.close()
    print("✓ Conexión cerrada")
except Exception as e:
    print(f"✗ ERROR BD: {e}")
    traceback.print_exc()

print("\n3. Verificando variables de entorno...")
import os
vars_check = ['DB_HOST', 'DB_NAME', 'DB_USER', 'JWT_SECRET_KEY']
for var in vars_check:
    val = os.getenv(var)
    if val:
        print(f"✓ {var} = {'*' * len(val)}")
    else:
        print(f"✗ {var} NO configurada")

print("\n=== FIN DIAGNÓSTICO ===")

