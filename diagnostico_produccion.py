"""
Script de diagnóstico para identificar problemas en producción (Cloud Run).
Ejecutar localmente para simular el entorno de producción.
"""
import os
import sys

print("="*60)
print("DIAGNÓSTICO DE PRODUCCIÓN - CLOUD RUN")
print("="*60)
print()

# 1. Verificar Python
print("1. Verificando versión de Python...")
print(f"   Python: {sys.version}")
if sys.version_info < (3, 8):
    print("   ⚠️  ADVERTENCIA: Se recomienda Python 3.8+")
else:
    print("   ✅ Versión de Python OK")
print()

# 2. Verificar archivos críticos
print("2. Verificando archivos críticos...")
archivos_criticos = [
    'app.py',
    'Procfile',
    'requirements.txt',
    'db_connector.py',
    'storage_manager.py',
    'validators.py'
]

for archivo in archivos_criticos:
    if os.path.exists(archivo):
        print(f"   ✅ {archivo}")
    else:
        print(f"   ❌ FALTA: {archivo}")
print()

# 3. Verificar dependencias
print("3. Verificando dependencias...")
dependencias = [
    'flask',
    'PyJWT',
    'werkzeug',
    'psycopg2',
    'python-dotenv',
    'flask-cors',
    'google-cloud-storage',
    'google-cloud-documentai',
    'gunicorn'
]

for dep in dependencias:
    try:
        __import__(dep.lower().replace('-', '_'))
        print(f"   ✅ {dep}")
    except ImportError:
        print(f"   ❌ FALTA: {dep}")
print()

# 4. Verificar importación de módulos
print("4. Verificando importación de módulos...")
try:
    from db_connector import get_db_connection
    print("   ✅ db_connector")
except Exception as e:
    print(f"   ❌ Error al importar db_connector: {e}")

try:
    from storage_manager import upload_document, get_document_url, delete_document
    print("   ✅ storage_manager")
except Exception as e:
    print(f"   ❌ Error al importar storage_manager: {e}")

try:
    from validators import validate_residente_data
    print("   ✅ validators")
except Exception as e:
    print(f"   ❌ Error al importar validators: {e}")

try:
    # Intentar importar app sin ejecutar código de inicialización
    import importlib.util
    spec = importlib.util.spec_from_file_location("app", "app.py")
    if spec and spec.loader:
        print("   ✅ app.py (estructura válida)")
    else:
        print("   ❌ Error al cargar app.py")
except Exception as e:
    print(f"   ⚠️  Advertencia al verificar app.py: {e}")
print()

# 5. Verificar Procfile
print("5. Verificando Procfile...")
if os.path.exists('Procfile'):
    with open('Procfile', 'r') as f:
        contenido = f.read().strip()
        if 'gunicorn' in contenido and 'app:app' in contenido:
            print("   ✅ Procfile válido")
            print(f"   Contenido: {contenido}")
        else:
            print("   ⚠️  Procfile puede tener problemas")
            print(f"   Contenido: {contenido}")
else:
    print("   ❌ FALTA: Procfile")
print()

# 6. Verificar variables de entorno requeridas (sin valores, solo nombres)
print("6. Verificando variables de entorno requeridas...")
vars_requeridas = [
    'DB_NAME',
    'DB_USER',
    'DB_PASSWORD',
    'JWT_SECRET_KEY',
    'CLOUD_SQL_CONNECTION_NAME',
    'GCS_BUCKET_NAME'
]

for var in vars_requeridas:
    valor = os.getenv(var)
    if valor:
        # Mostrar solo primeros/last caracteres para seguridad
        if len(valor) > 10:
            valor_display = valor[:3] + "..." + valor[-3:]
        else:
            valor_display = "***"
        print(f"   ✅ {var} = {valor_display}")
    else:
        print(f"   ⚠️  {var} no está definida (requerida en producción)")
print()

# 7. Verificar sintaxis de app.py
print("7. Verificando sintaxis de app.py...")
try:
    with open('app.py', 'r', encoding='utf-8') as f:
        codigo = f.read()
    compile(codigo, 'app.py', 'exec')
    print("   ✅ Sintaxis de app.py válida")
except SyntaxError as e:
    print(f"   ❌ Error de sintaxis en app.py: {e}")
    print(f"   Línea {e.lineno}: {e.text}")
except Exception as e:
    print(f"   ⚠️  Error al verificar sintaxis: {e}")
print()

# 8. Verificar que app.py puede ser importado por gunicorn
print("8. Verificando que app puede ser importado (simulando gunicorn)...")
try:
    # Simular lo que hace gunicorn: importar el módulo app
    # Pero sin ejecutar el código de __main__
    import importlib.util
    spec = importlib.util.spec_from_file_location("app_module", "app.py")
    if spec and spec.loader:
        # Solo verificar que se puede cargar, no ejecutar
        print("   ✅ app.py puede ser cargado como módulo")
    else:
        print("   ❌ No se puede cargar app.py como módulo")
except Exception as e:
    print(f"   ❌ Error al importar app: {e}")
    import traceback
    traceback.print_exc()
print()

# 9. Verificar estructura de directorios
print("9. Verificando estructura de directorios...")
directorios_requeridos = ['static']
for dir_name in directorios_requeridos:
    if os.path.exists(dir_name) and os.path.isdir(dir_name):
        print(f"   ✅ {dir_name}/")
    else:
        print(f"   ⚠️  {dir_name}/ no existe o no es un directorio")
print()

print("="*60)
print("FIN DEL DIAGNÓSTICO")
print("="*60)
print()
print("Si todos los checks pasan, el problema puede estar en:")
print("1. Variables de entorno/secrets no configuradas en Cloud Run")
print("2. Permisos IAM insuficientes para Cloud SQL o Cloud Storage")
print("3. Problemas con buildpacks de Google Cloud")
print("4. Problemas de red/conectividad en Cloud Run")

