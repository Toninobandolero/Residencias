"""
Script para actualizar el archivo .env con las credenciales de Cloud Storage.
"""
import os

def actualizar_env():
    """Actualiza el archivo .env con las credenciales de GCS."""
    env_file = '.env'
    
    # Leer .env actual si existe
    lines = []
    if os.path.exists(env_file):
        with open(env_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    
    # Variables a agregar/actualizar
    gcs_vars = {
        'GCS_BUCKET_NAME': 'violetas-documentos',
        'GOOGLE_APPLICATION_CREDENTIALS': 'residencias-479706-8c3bdbf8bbf8.json'
    }
    
    # Verificar si las variables ya existen
    existing_vars = {}
    new_lines = []
    in_gcs_section = False
    
    for line in lines:
        stripped = line.strip()
        
        # Detectar sección de GCS
        if '# Google Cloud Storage' in line:
            in_gcs_section = True
            new_lines.append(line)
            continue
        
        # Si estamos en la sección GCS, saltar líneas hasta encontrar otra sección
        if in_gcs_section:
            if stripped.startswith('#') and 'Google Cloud Storage' not in line:
                in_gcs_section = False
                # Agregar variables GCS antes de esta línea
                if 'GCS_BUCKET_NAME' not in existing_vars:
                    new_lines.append(f"GCS_BUCKET_NAME={gcs_vars['GCS_BUCKET_NAME']}\n")
                if 'GOOGLE_APPLICATION_CREDENTIALS' not in existing_vars:
                    new_lines.append(f"GOOGLE_APPLICATION_CREDENTIALS={gcs_vars['GOOGLE_APPLICATION_CREDENTIALS']}\n")
                new_lines.append("\n")
                new_lines.append(line)
                continue
            elif '=' in stripped and not stripped.startswith('#'):
                key = stripped.split('=')[0].strip()
                if key in gcs_vars:
                    existing_vars[key] = True
                    # Actualizar el valor
                    new_lines.append(f"{key}={gcs_vars[key]}\n")
                    continue
        
        new_lines.append(line)
    
    # Si no había sección GCS, agregarla al final
    if not in_gcs_section and 'GCS_BUCKET_NAME' not in existing_vars:
        # Buscar si hay una línea en blanco al final
        if new_lines and new_lines[-1].strip():
            new_lines.append("\n")
        new_lines.append("# Google Cloud Storage\n")
        new_lines.append(f"GCS_BUCKET_NAME={gcs_vars['GCS_BUCKET_NAME']}\n")
        new_lines.append(f"GOOGLE_APPLICATION_CREDENTIALS={gcs_vars['GOOGLE_APPLICATION_CREDENTIALS']}\n")
    
    # Escribir el archivo actualizado
    with open(env_file, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print("✅ Archivo .env actualizado con las credenciales de Cloud Storage")
    print(f"   GCS_BUCKET_NAME={gcs_vars['GCS_BUCKET_NAME']}")
    print(f"   GOOGLE_APPLICATION_CREDENTIALS={gcs_vars['GOOGLE_APPLICATION_CREDENTIALS']}")
    
    # Verificar que el archivo de credenciales existe
    if os.path.exists(gcs_vars['GOOGLE_APPLICATION_CREDENTIALS']):
        print(f"✅ Archivo de credenciales encontrado: {gcs_vars['GOOGLE_APPLICATION_CREDENTIALS']}")
    else:
        print(f"⚠️  Archivo de credenciales NO encontrado: {gcs_vars['GOOGLE_APPLICATION_CREDENTIALS']}")
        print("   Asegúrate de que el archivo JSON esté en la carpeta del proyecto")


if __name__ == '__main__':
    actualizar_env()

