"""
Script para resetear la contraseña del superadmin.
Útil si olvidaste la contraseña o necesitas restaurarla.
"""
from werkzeug.security import generate_password_hash, check_password_hash
from db_connector import get_db_connection
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def reset_superadmin_password():
    """
    Resetea la contraseña del superadmin a la contraseña por defecto.
    """
    SUPER_ADMIN_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'admin@residencias.com')
    SUPER_ADMIN_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', 'CambiarContraseña123!')
    
    print(f"\n{'='*60}")
    print("RESETEAR CONTRASEÑA DE SUPERADMIN")
    print(f"{'='*60}")
    print(f"Email: {SUPER_ADMIN_EMAIL}")
    print(f"Nueva contraseña: {SUPER_ADMIN_PASSWORD}")
    print(f"{'='*60}\n")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Buscar el superadmin
        cursor.execute("""
            SELECT id_usuario, email, password_hash, id_rol, activo
            FROM usuario 
            WHERE id_rol = 1 AND email = %s
        """, (SUPER_ADMIN_EMAIL,))
        
        usuario = cursor.fetchone()
        
        if not usuario:
            print(f"❌ ERROR: No se encontró el superadmin con email {SUPER_ADMIN_EMAIL}")
            print("   Verifica que el usuario exista en la base de datos.")
            return False
        
        id_usuario, email_db, password_hash_actual, id_rol, activo = usuario
        
        print(f"✅ Usuario encontrado:")
        print(f"   ID: {id_usuario}")
        print(f"   Email: {email_db}")
        print(f"   Rol: {id_rol}")
        print(f"   Activo: {activo}")
        
        # Generar nuevo hash de contraseña
        nuevo_password_hash = generate_password_hash(SUPER_ADMIN_PASSWORD)
        
        # Actualizar contraseña y marcar como requiere cambio
        cursor.execute("""
            UPDATE usuario 
            SET password_hash = %s,
                requiere_cambio_clave = TRUE
            WHERE id_usuario = %s
        """, (nuevo_password_hash, id_usuario))
        
        conn.commit()
        
        print(f"\n✅ Contraseña reseteada exitosamente")
        print(f"   Nueva contraseña: {SUPER_ADMIN_PASSWORD}")
        print(f"   ⚠️  IMPORTANTE: Deberás cambiar la contraseña en el primer login")
        print(f"\n{'='*60}\n")
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"❌ ERROR al resetear contraseña: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False
    finally:
        cursor.close()
        conn.close()

def verificar_superadmin():
    """
    Verifica las credenciales del superadmin sin cambiarlas.
    """
    SUPER_ADMIN_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'admin@residencias.com')
    SUPER_ADMIN_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', 'CambiarContraseña123!')
    
    print(f"\n{'='*60}")
    print("VERIFICAR CREDENCIALES DE SUPERADMIN")
    print(f"{'='*60}")
    print(f"Email: {SUPER_ADMIN_EMAIL}")
    print(f"Contraseña a verificar: {SUPER_ADMIN_PASSWORD}")
    print(f"{'='*60}\n")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Buscar el superadmin
        cursor.execute("""
            SELECT id_usuario, email, password_hash, id_rol, activo, requiere_cambio_clave
            FROM usuario 
            WHERE id_rol = 1 AND email = %s
        """, (SUPER_ADMIN_EMAIL,))
        
        usuario = cursor.fetchone()
        
        if not usuario:
            print(f"❌ ERROR: No se encontró el superadmin con email {SUPER_ADMIN_EMAIL}")
            return False
        
        id_usuario, email_db, password_hash, id_rol, activo, requiere_cambio_clave = usuario
        
        print(f"✅ Usuario encontrado:")
        print(f"   ID: {id_usuario}")
        print(f"   Email: {email_db}")
        print(f"   Rol: {id_rol}")
        print(f"   Activo: {activo}")
        print(f"   Requiere cambio de clave: {requiere_cambio_clave}")
        
        # Verificar contraseña
        password_valida = check_password_hash(password_hash, SUPER_ADMIN_PASSWORD)
        
        print(f"\n{'='*60}")
        if password_valida:
            print("✅ CONTRASEÑA VÁLIDA")
            print(f"   La contraseña '{SUPER_ADMIN_PASSWORD}' es correcta")
        else:
            print("❌ CONTRASEÑA INVÁLIDA")
            print(f"   La contraseña '{SUPER_ADMIN_PASSWORD}' NO coincide con el hash almacenado")
            print(f"   La contraseña fue cambiada o el hash está corrupto")
        print(f"{'='*60}\n")
        
        return password_valida
        
    except Exception as e:
        print(f"❌ ERROR al verificar credenciales: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'reset':
        print("\n⚠️  ADVERTENCIA: Se reseteará la contraseña del superadmin")
        respuesta = input("¿Continuar? (s/n): ")
        if respuesta.lower() == 's':
            reset_superadmin_password()
        else:
            print("Operación cancelada.")
    else:
        # Por defecto, solo verificar
        verificar_superadmin()
        print("\n💡 Para resetear la contraseña, ejecuta:")
        print("   python reset_superadmin_password.py reset")

