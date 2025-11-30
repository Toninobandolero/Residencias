"""
Módulo para gestionar el almacenamiento de documentos en Google Cloud Storage.
"""
import os
from google.cloud import storage
from datetime import datetime, timedelta

# Inicializar cliente de Cloud Storage
def get_storage_client():
    """Obtiene el cliente de Cloud Storage."""
    try:
        # Si hay credenciales en variable de entorno, usarlas
        credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        if credentials_path and os.path.exists(credentials_path):
            return storage.Client.from_service_account_json(credentials_path)
        else:
            # Intentar usar credenciales por defecto (para Cloud Run)
            return storage.Client()
    except Exception as e:
        error_msg = f"Error al inicializar cliente de Cloud Storage: {str(e)}. Verifique que GOOGLE_APPLICATION_CREDENTIALS esté configurado o que las credenciales por defecto estén disponibles."
        print(error_msg)
        raise Exception(error_msg)


def upload_document(file_content, id_residencia, id_residente, tipo_documento, nombre_archivo, content_type=None):
    """
    Sube un documento a Cloud Storage.
    
    Args:
        file_content: Contenido del archivo (bytes)
        id_residencia: ID de la residencia
        id_residente: ID del residente
        tipo_documento: Tipo de documento (Médica, Bancaria, etc.)
        nombre_archivo: Nombre del archivo
        content_type: Tipo MIME del archivo (opcional)
    
    Returns:
        str: Ruta del archivo en Cloud Storage (blob_path), o None si hay error
    """
    try:
        client = get_storage_client()
        
        bucket_name = os.getenv('GCS_BUCKET_NAME', 'violetas-documentos')
        bucket = client.bucket(bucket_name)
        
        # Verificar que el bucket existe
        if not bucket.exists():
            error_msg = f"El bucket '{bucket_name}' no existe en Cloud Storage. Verifique que GCS_BUCKET_NAME esté configurado correctamente."
            print(error_msg)
            raise Exception(error_msg)
        
        # Crear ruta: residencia-{id}/residente-{id}/tipo-fecha-nombre
        fecha = datetime.now().strftime('%Y%m%d')
        timestamp = datetime.now().strftime('%H%M%S')
        extension = os.path.splitext(nombre_archivo)[1] or '.pdf'
        nombre_safe = nombre_archivo.replace(' ', '_').replace('/', '_').replace('\\', '_')
        tipo_safe = tipo_documento.lower().replace(' ', '_')
        
        blob_path = f"residencia-{id_residencia}/residente-{id_residente}/{tipo_safe}-{fecha}-{timestamp}{extension}"
        
        # Determinar content type si no se proporciona
        if not content_type:
            import mimetypes
            content_type, _ = mimetypes.guess_type(nombre_archivo)
            if not content_type:
                content_type = 'application/octet-stream'
        
        blob = bucket.blob(blob_path)
        blob.upload_from_string(file_content, content_type=content_type)
        
        # Intentar hacer el blob privado (si no tiene permisos, continuar de todas formas)
        try:
            blob.make_private()
        except Exception as make_private_error:
            # Si no tiene permisos para cambiar IAM, el blob seguirá siendo accesible solo con URLs firmadas
            # que es lo que necesitamos de todas formas
            print(f"Advertencia: No se pudo hacer el blob privado (esto es normal si no hay permisos IAM): {str(make_private_error)}")
        
        return blob_path
        
    except Exception as e:
        import traceback
        error_msg = f"Error al subir documento: {str(e)}"
        print(error_msg)
        print(traceback.format_exc())
        # Re-lanzar el error para que el backend lo capture con más detalles
        raise Exception(f"Error al subir documento a Cloud Storage: {str(e)}")


def get_document_url(blob_path, expiration_minutes=60):
    """
    Genera una URL firmada temporal para descargar un documento.
    
    Args:
        blob_path: Ruta del archivo en Cloud Storage
        expiration_minutes: Minutos hasta que expire la URL
    
    Returns:
        str: URL firmada, o None si hay error
    """
    try:
        client = get_storage_client()
        if not client:
            return None
        
        bucket_name = os.getenv('GCS_BUCKET_NAME', 'violetas-documentos')
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_path)
        
        # Generar URL firmada válida por 1 hora
        url = blob.generate_signed_url(
            expiration=datetime.utcnow() + timedelta(minutes=expiration_minutes),
            method='GET'
        )
        
        return url
        
    except Exception as e:
        print(f"Error al generar URL: {str(e)}")
        return None


def delete_document(blob_path):
    """
    Elimina un documento de Cloud Storage.
    
    Args:
        blob_path: Ruta del archivo en Cloud Storage
    
    Returns:
        bool: True si se eliminó correctamente, False en caso contrario
    """
    try:
        client = get_storage_client()
        if not client:
            return False
        
        bucket_name = os.getenv('GCS_BUCKET_NAME', 'violetas-documentos')
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_path)
        
        blob.delete()
        return True
        
    except Exception as e:
        print(f"Error al eliminar documento: {str(e)}")
        return False

