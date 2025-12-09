"""
Script para simular exactamente lo que hace gunicorn al iniciar.
Esto ayuda a identificar problemas antes del despliegue.
"""
import os
import sys

print("="*60)
print("SIMULANDO INICIO DE GUNICORN")
print("="*60)
print()

# Simular entorno de Cloud Run (sin .env, con variables mínimas)
print("1. Configurando entorno simulado de Cloud Run...")
# No cargar .env para simular producción
if '.env' in os.environ:
    del os.environ['.env']

# Variables mínimas que Cloud Run debería tener
env_vars_required = [
    'DB_NAME',
    'DB_USER', 
    'DB_PASSWORD',
    'JWT_SECRET_KEY',
    'CLOUD_SQL_CONNECTION_NAME',
    'GCS_BUCKET_NAME'
]

print("   Variables requeridas:")
for var in env_vars_required:
    if os.getenv(var):
        print(f"   ✅ {var} = {'*' * min(len(os.getenv(var)), 10)}")
    else:
        print(f"   ⚠️  {var} NO definida (esto causaría error en Cloud Run)")

print()
print("2. Intentando importar 'app' (como hace gunicorn)...")
print("   Comando simulado: python -c 'import app; app = app.app'")
print()

try:
    # Esto es exactamente lo que hace gunicorn
    import app
    print("   ✅ Módulo 'app' importado")
    
    # Verificar que app.app existe
    flask_app = app.app
    print("   ✅ app.app existe")
    
    # Verificar que es Flask
    from flask import Flask
    if isinstance(flask_app, Flask):
        print("   ✅ Es una instancia de Flask")
    else:
        print(f"   ❌ No es Flask: {type(flask_app)}")
        sys.exit(1)
        
except ValueError as e:
    if 'JWT_SECRET_KEY' in str(e):
        print(f"   ❌ ERROR: {e}")
        print("   ⚠️  JWT_SECRET_KEY no está definida")
        print("   💡 En Cloud Run, esto debería venir de --set-secrets")
        sys.exit(1)
    else:
        print(f"   ❌ ValueError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
        
except ImportError as e:
    print(f"   ❌ ImportError: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
    
except Exception as e:
    print(f"   ❌ Error inesperado: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()
print("="*60)
print("✅ SIMULACIÓN EXITOSA")
print("="*60)
print()
print("Si esto funciona pero Cloud Run falla, el problema puede ser:")
print("1. Variables de entorno/secrets no configuradas correctamente")
print("2. Permisos IAM insuficientes")
print("3. Problema con la conexión a Cloud SQL")
print()

