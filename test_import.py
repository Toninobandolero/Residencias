#!/usr/bin/env python3
"""Script para probar que la app se puede importar sin errores"""
import sys
import os

# Simular variables de entorno mínimas para Cloud Run
os.environ.setdefault('JWT_SECRET_KEY', 'test-secret-for-import')
os.environ.setdefault('DB_PASSWORD', 'test-password-for-import')
os.environ.setdefault('DB_NAME', 'postgres')
os.environ.setdefault('DB_USER', 'postgres')
os.environ.setdefault('PORT', '8080')

print("Intentando importar app...")
try:
    import app
    print("✓ app importado correctamente")
    print(f"✓ app.app es: {type(app.app)}")
    print("✓ Todo OK")
    sys.exit(0)
except Exception as e:
    print(f"✗ ERROR al importar: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)


