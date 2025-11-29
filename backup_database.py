"""
Script para realizar backup de la base de datos PostgreSQL.
Crea un archivo SQL con el dump completo de la base de datos.
"""
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

def create_backup():
    """Crea un backup de la base de datos."""
    try:
        import subprocess
    except ImportError:
        print("❌ Error: No se puede importar subprocess")
        sys.exit(1)
    
    # Obtener variables de entorno
    db_host = os.getenv('DB_HOST')
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_port = os.getenv('DB_PORT', '5432')
    
    if not all([db_host, db_name, db_user, db_password]):
        print("❌ Error: Faltan variables de entorno requeridas")
        print("   Asegúrate de tener DB_HOST, DB_NAME, DB_USER, DB_PASSWORD en .env")
        sys.exit(1)
    
    # Crear directorio de backups si no existe
    backup_dir = 'backups'
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
        print(f"✓ Directorio '{backup_dir}' creado")
    
    # Nombre del archivo de backup
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"backup_violetas_{timestamp}.sql"
    backup_path = os.path.join(backup_dir, backup_filename)
    
    print(f"\n🔄 Creando backup de la base de datos...")
    print(f"   Host: {db_host}")
    print(f"   Base de datos: {db_name}")
    print(f"   Usuario: {db_user}")
    print(f"   Archivo: {backup_path}")
    
    # Comando pg_dump
    # Nota: pg_dump debe estar instalado en el sistema
    env = os.environ.copy()
    env['PGPASSWORD'] = db_password
    
    try:
        cmd = [
            'pg_dump',
            '-h', db_host,
            '-p', db_port,
            '-U', db_user,
            '-d', db_name,
            '-F', 'p',  # Formato texto plano
            '-f', backup_path,
            '--no-owner',  # No incluir comandos de ownership
            '--no-acl'     # No incluir permisos
        ]
        
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutos máximo
        )
        
        if result.returncode == 0:
            # Obtener tamaño del archivo
            file_size = os.path.getsize(backup_path)
            size_mb = file_size / (1024 * 1024)
            
            print(f"\n✅ Backup creado exitosamente!")
            print(f"   Archivo: {backup_path}")
            print(f"   Tamaño: {size_mb:.2f} MB")
            print(f"\n💡 Para restaurar el backup, usa:")
            print(f"   psql -h {db_host} -p {db_port} -U {db_user} -d {db_name} < {backup_path}")
            
            # Mantener solo los últimos 10 backups
            cleanup_old_backups(backup_dir, keep=10)
            
            return backup_path
        else:
            print(f"\n❌ Error al crear backup:")
            print(f"   {result.stderr}")
            sys.exit(1)
            
    except FileNotFoundError:
        print("\n❌ Error: pg_dump no está instalado o no está en el PATH")
        print("   Instala PostgreSQL client tools:")
        print("   - Windows: Descarga desde https://www.postgresql.org/download/windows/")
        print("   - Linux: sudo apt-get install postgresql-client")
        print("   - macOS: brew install postgresql")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("\n❌ Error: El backup tardó demasiado (más de 5 minutos)")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error inesperado: {str(e)}")
        sys.exit(1)


def cleanup_old_backups(backup_dir, keep=10):
    """Elimina backups antiguos, manteniendo solo los últimos N."""
    try:
        import glob
        
        # Obtener todos los archivos de backup
        backup_files = glob.glob(os.path.join(backup_dir, 'backup_violetas_*.sql'))
        
        # Ordenar por fecha de modificación (más reciente primero)
        backup_files.sort(key=os.path.getmtime, reverse=True)
        
        # Eliminar los más antiguos
        if len(backup_files) > keep:
            deleted = 0
            for old_backup in backup_files[keep:]:
                try:
                    os.remove(old_backup)
                    deleted += 1
                except Exception as e:
                    print(f"⚠️  No se pudo eliminar {old_backup}: {e}")
            
            if deleted > 0:
                print(f"   🗑️  Eliminados {deleted} backup(s) antiguo(s)")
    except Exception as e:
        print(f"⚠️  Error al limpiar backups antiguos: {e}")


if __name__ == '__main__':
    print("=" * 60)
    print("BACKUP DE BASE DE DATOS - Sistema Violetas")
    print("=" * 60)
    create_backup()

