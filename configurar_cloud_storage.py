"""
Script interactivo para configurar Google Cloud Storage.
Ayuda a crear el bucket y configurar las variables de entorno.
"""
import os
import json
from dotenv import load_dotenv

load_dotenv()


def configurar_gcs():
    """Guía interactiva para configurar Cloud Storage."""
    print("\n" + "="*60)
    print("CONFIGURACIÓN DE GOOGLE CLOUD STORAGE")
    print("="*60)
    
    print("\n📋 Pasos para configurar Cloud Storage:")
    print("\n1. Crear el bucket en Google Cloud Console:")
    print("   - Ve a: https://console.cloud.google.com/storage")
    print("   - Click en 'CREATE BUCKET'")
    print("   - Nombre: violetas-documentos (o el que prefieras)")
    print("   - Location: europe-west9 (misma región que Cloud SQL)")
    print("   - Storage class: Standard")
    print("   - Access control: Uniform")
    
    print("\n2. Configurar permisos IAM:")
    print("   - Ve a: IAM & Admin > Service Accounts")
    print("   - Crea una cuenta de servicio o usa la de Cloud Run")
    print("   - Asigna el rol: Storage Object Admin")
    
    print("\n3. Obtener credenciales (para desarrollo local):")
    print("   - En Service Accounts, crea una clave JSON")
    print("   - Descarga el archivo JSON")
    print("   - Guárdalo en la carpeta del proyecto")
    
    print("\n" + "="*60)
    
    # Solicitar información
    bucket_name = input("\n📦 Nombre del bucket (o Enter para 'violetas-documentos'): ").strip()
    if not bucket_name:
        bucket_name = 'violetas-documentos'
    
    credentials_path = input("\n🔑 Ruta al archivo JSON de credenciales (o Enter para usar credenciales por defecto): ").strip()
    
    # Leer .env actual
    env_file = '.env'
    env_vars = {}
    
    if os.path.exists(env_file):
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    
    # Actualizar variables
    env_vars['GCS_BUCKET_NAME'] = bucket_name
    if credentials_path and os.path.exists(credentials_path):
        # Convertir a ruta absoluta
        abs_path = os.path.abspath(credentials_path)
        env_vars['GOOGLE_APPLICATION_CREDENTIALS'] = abs_path
        print(f"\n✅ Credenciales configuradas: {abs_path}")
    else:
        if 'GOOGLE_APPLICATION_CREDENTIALS' in env_vars:
            del env_vars['GOOGLE_APPLICATION_CREDENTIALS']
        print("\n⚠️  Usando credenciales por defecto (Cloud Run o gcloud)")
    
    # Escribir .env
    with open(env_file, 'w', encoding='utf-8') as f:
        f.write("# Variables de entorno para el backend Violetas\n\n")
        f.write("# Base de datos PostgreSQL (Cloud SQL en GCP)\n")
        for key in ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_PORT']:
            if key in env_vars:
                f.write(f"{key}={env_vars[key]}\n")
        
        f.write("\n# JWT Secret Key\n")
        if 'JWT_SECRET_KEY' in env_vars:
            f.write(f"JWT_SECRET_KEY={env_vars['JWT_SECRET_KEY']}\n")
        
        f.write("\n# Google Cloud Storage\n")
        f.write(f"GCS_BUCKET_NAME={bucket_name}\n")
        if credentials_path and os.path.exists(credentials_path):
            f.write(f"GOOGLE_APPLICATION_CREDENTIALS={os.path.abspath(credentials_path)}\n")
    
    print(f"\n✅ Variables de entorno actualizadas en .env")
    print(f"   GCS_BUCKET_NAME={bucket_name}")
    
    # Verificar instalación de google-cloud-storage
    print("\n📦 Verificando dependencias...")
    try:
        import google.cloud.storage
        print("✅ google-cloud-storage está instalado")
    except ImportError:
        print("❌ google-cloud-storage NO está instalado")
        print("   Ejecuta: pip install google-cloud-storage")
        return False
    
    # Probar conexión si hay credenciales
    if credentials_path and os.path.exists(credentials_path):
        print("\n🔍 Probando conexión a Cloud Storage...")
        try:
            from storage_manager import get_storage_client
            client = get_storage_client()
            if client:
                bucket = client.bucket(bucket_name)
                if bucket.exists():
                    print(f"✅ Bucket '{bucket_name}' encontrado y accesible")
                else:
                    print(f"⚠️  Bucket '{bucket_name}' no existe. Créalo en la consola de GCP.")
            else:
                print("⚠️  No se pudo inicializar el cliente. Verifica las credenciales.")
        except Exception as e:
            print(f"⚠️  Error al probar conexión: {str(e)}")
            print("   Esto es normal si el bucket aún no existe.")
    
    print("\n" + "="*60)
    print("✅ Configuración completada!")
    print("\n📝 Próximos pasos:")
    print("   1. Crea el bucket en Google Cloud Console si no existe")
    print("   2. Configura los permisos IAM")
    print("   3. Reinicia el servidor Flask")
    print("\n" + "="*60)
    
    return True


if __name__ == '__main__':
    configurar_gcs()

