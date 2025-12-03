"""
Script para actualizar la contraseña del superadmin con una contraseña específica.
"""
from werkzeug.security import generate_password_hash
from db_connector import get_db_connection
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def actualizar_contraseña():
    """
    Actualiza la contraseña del superadmin con la contraseña especificada.
    """
    SUPER_ADMIN_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'admin@residencias.com')
    NUEVA_CONTRASEÑA = '4#%%9V#CUxbSZ^KFMeHJVd'
    
    print(f"\n{'='*70}")
    print("ACTUALIZAR CONTRASEÑA DE SUPERADMIN")
    print(f"{'='*70}")
    print(f"Email: {SUPER_ADMIN_EMAIL}")
    print(f"Nueva contraseña: {NUEVA_CONTRASEÑA}")
    print(f"{'='*70}\n")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Buscar el usuario
        cursor.execute("""
            SELECT id_usuario, email, id_rol, activo
            FROM usuario 
            WHERE email = %s
        """, (SUPER_ADMIN_EMAIL,))
        
        usuario = cursor.fetchone()
        
        if not usuario:
            print(f"❌ ERROR: No se encontró el usuario con email {SUPER_ADMIN_EMAIL}")
            return False
        
        id_usuario, email_db, id_rol, activo = usuario
        
        print(f"✅ Usuario encontrado:")
        print(f"   ID: {id_usuario}")
        print(f"   Email: {email_db}")
        print(f"   Rol: {id_rol}")
        print(f"   Activo: {activo}")
        
        # Generar nuevo hash de contraseña
        print(f"\nGenerando nuevo hash de contraseña...")
        nuevo_password_hash = generate_password_hash(NUEVA_CONTRASEÑA)
        print(f"Hash generado: {nuevo_password_hash[:60]}...")
        
        # Actualizar contraseña
        print(f"\nActualizando contraseña en la base de datos...")
        cursor.execute("""
            UPDATE usuario 
            SET password_hash = %s
            WHERE id_usuario = %s
        """, (nuevo_password_hash, id_usuario))
        
        conn.commit()
        
        print(f"✅ Contraseña actualizada exitosamente")
        print(f"\n{'='*70}")
        print("RESUMEN")
        print(f"{'='*70}")
        print(f"✅ La contraseña '{NUEVA_CONTRASEÑA}' ha sido actualizada")
        print(f"✅ Ahora puedes hacer login con esta contraseña")
        print(f"{'='*70}\n")
        
        # Verificar que la actualización funcionó
        print("Verificando que la actualización funcionó...")
        cursor.execute("""
            SELECT password_hash FROM usuario WHERE id_usuario = %s
        """, (id_usuario,))
        hash_verificado = cursor.fetchone()[0]
        
        from werkzeug.security import check_password_hash
        if check_password_hash(hash_verificado, NUEVA_CONTRASEÑA):
            print("✅ Verificación exitosa: La contraseña funciona correctamente")
        else:
            print("❌ ERROR: La verificación falló después de actualizar")
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"❌ ERROR al actualizar contraseña: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--force':
        # Modo no interactivo
        actualizar_contraseña()
    else:
        print("\n⚠️  ADVERTENCIA: Se actualizará la contraseña del superadmin")
        print("   Esta operación sobrescribirá la contraseña actual")
        respuesta = input("\n¿Continuar? (s/n): ")
        if respuesta.lower() == 's':
            actualizar_contraseña()
        else:
            print("Operación cancelada.")

