"""
Script para probar la conexión con Google Cloud Storage.
"""
import os
from dotenv import load_dotenv

load_dotenv()


def test_cloud_storage():
    """Prueba la conexión con Cloud Storage."""
    print("\n" + "="*60)
    print("PRUEBA DE CONEXIÓN CON GOOGLE CLOUD STORAGE")
    print("="*60)
    
    # Verificar variables de entorno
    bucket_name = os.getenv('GCS_BUCKET_NAME', 'violetas-documentos')
    credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
    
    print(f"\n📦 Bucket configurado: {bucket_name}")
    if credentials_path:
        if os.path.exists(credentials_path):
            print(f"✅ Credenciales encontradas: {credentials_path}")
        else:
            print(f"❌ Credenciales NO encontradas: {credentials_path}")
            return False
    else:
        print("⚠️  No hay credenciales configuradas (usará credenciales por defecto)")
    
    # Verificar instalación de google-cloud-storage
    try:
        from google.cloud import storage
        print("✅ google-cloud-storage está instalado")
    except ImportError:
        print("❌ google-cloud-storage NO está instalado")
        print("   Ejecuta: pip install google-cloud-storage")
        return False
    
    # Probar conexión
    try:
        from storage_manager import get_storage_client
        
        print("\n🔍 Probando conexión...")
        client = get_storage_client()
        
        if not client:
            print("❌ No se pudo crear el cliente de Cloud Storage")
            return False
        
        print("✅ Cliente de Cloud Storage creado exitosamente")
        
        # Verificar bucket
        bucket = client.bucket(bucket_name)
        if bucket.exists():
            print(f"✅ Bucket '{bucket_name}' existe y es accesible")
            
            # Listar algunos objetos (opcional)
            blobs = list(bucket.list_blobs(max_results=5))
            print(f"📄 Archivos en el bucket: {len(blobs)} (mostrando primeros 5)")
            for blob in blobs:
                print(f"   - {blob.name}")
            
            return True
        else:
            print(f"❌ Bucket '{bucket_name}' NO existe")
            print("\n📝 Para crear el bucket:")
            print("   1. Ve a: https://console.cloud.google.com/storage")
            print("   2. Click en 'CREATE BUCKET'")
            print(f"   3. Nombre: {bucket_name}")
            print("   4. Location: europe-west9")
            print("   5. Storage class: Standard")
            return False
        
    except Exception as e:
        print(f"❌ Error al probar conexión: {str(e)}")
        print("\n💡 Posibles causas:")
        print("   - El bucket no existe (créalo en Cloud Console)")
        print("   - Las credenciales no tienen permisos")
        print("   - El proyecto no está configurado correctamente")
        return False


if __name__ == '__main__':
    success = test_cloud_storage()
    print("\n" + "="*60)
    if success:
        print("✅ Cloud Storage está configurado correctamente!")
    else:
        print("❌ Hay problemas con la configuración. Revisa los mensajes arriba.")
    print("="*60 + "\n")

