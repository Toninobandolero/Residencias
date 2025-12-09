"""
Test exacto de lo que hace gunicorn: importar app:app
"""
import sys
import os

# Simular entorno de Cloud Run
os.environ.pop('PYTHONPATH', None)

print("="*60)
print("TEST EXACTO: gunicorn app:app")
print("="*60)
print()

# Esto es exactamente lo que hace gunicorn
try:
    print("1. Importando módulo 'app'...")
    import app
    print("   ✅ Módulo importado")
    
    print()
    print("2. Accediendo a app.app...")
    flask_app = app.app
    print(f"   ✅ app.app = {type(flask_app)}")
    
    print()
    print("3. Verificando que es Flask...")
    from flask import Flask
    if isinstance(flask_app, Flask):
        print("   ✅ Es una instancia de Flask")
    else:
        print(f"   ❌ No es Flask: {type(flask_app)}")
        sys.exit(1)
    
    print()
    print("4. Verificando que tiene rutas...")
    print(f"   ✅ Rutas registradas: {len(flask_app.url_map._rules)}")
    
    print()
    print("="*60)
    print("✅ TODO CORRECTO - Gunicorn debería poder iniciar")
    print("="*60)
    
except Exception as e:
    print()
    print("="*60)
    print("❌ ERROR AL IMPORTAR")
    print("="*60)
    print(f"Tipo: {type(e).__name__}")
    print(f"Mensaje: {e}")
    print()
    import traceback
    traceback.print_exc()
    sys.exit(1)

