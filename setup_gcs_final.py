"""Script final para configurar Cloud Storage"""
import os

# Agregar variables al .env
env_file = '.env'
gcs_config = """

# Google Cloud Storage
GCS_BUCKET_NAME=violetas-documentos
GOOGLE_APPLICATION_CREDENTIALS=residencias-479706-8c3bdbf8bbf8.json
"""

with open(env_file, 'a', encoding='utf-8') as f:
    f.write(gcs_config)

print("✅ Variables agregadas al .env")
print("✅ Configuración completada!")
print("\nAhora ejecuta: python test_cloud_storage.py")

