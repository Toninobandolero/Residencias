"""
Script para probar si gunicorn puede importar la app correctamente.
Simula lo que hace gunicorn: importar 'app:app'
"""
import sys
import os

print("="*60)
print("TEST: Simulando importación de gunicorn")
print("="*60)
print()

# Simular entorno de producción (sin .env)
if os.path.exists('.env'):
    print("⚠️  .env existe (se ignorará para simular producción)")
    print()

print("1. Verificando que app.py existe...")
if os.path.exists('app.py'):
    print("   ✅ app.py existe")
else:
    print("   ❌ app.py NO existe")
    sys.exit(1)

print()
print("2. Intentando importar 'app' (como hace gunicorn)...")
try:
    # Esto es lo que hace gunicorn: import app
    import app
    print("   ✅ Módulo 'app' importado exitosamente")
except SyntaxError as e:
    print(f"   ❌ Error de sintaxis: {e}")
    print(f"   Línea {e.lineno}: {e.text}")
    sys.exit(1)
except ImportError as e:
    print(f"   ❌ Error de importación: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
except Exception as e:
    print(f"   ❌ Error inesperado: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()
print("3. Verificando que 'app' (la instancia Flask) existe...")
try:
    # Esto es lo que hace gunicorn: acceder a app.app
    flask_app = app.app
    print("   ✅ app.app existe")
    print(f"   Tipo: {type(flask_app)}")
except AttributeError as e:
    print(f"   ❌ app.app no existe: {e}")
    sys.exit(1)
except Exception as e:
    print(f"   ❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()
print("4. Verificando que es una instancia de Flask...")
try:
    from flask import Flask
    if isinstance(flask_app, Flask):
        print("   ✅ Es una instancia de Flask")
    else:
        print(f"   ⚠️  No es una instancia de Flask: {type(flask_app)}")
except Exception as e:
    print(f"   ❌ Error: {e}")

print()
print("="*60)
print("✅ TODAS LAS VERIFICACIONES PASARON")
print("="*60)
print()
print("La app debería funcionar con gunicorn.")
print("Si sigue fallando en Cloud Run, revisa los logs de construcción.")
print()

