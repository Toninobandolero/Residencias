"""
Script para verificar una contraseña específica contra el hash almacenado.
"""
from werkzeug.security import check_password_hash
from db_connector import get_db_connection
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def verificar_contraseña_especifica():
    """
    Verifica una contraseña específica contra el hash almacenado.
    """
    SUPER_ADMIN_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'admin@residencias.com')
    CONTRASEÑA_A_VERIFICAR = '4#%%9V#CUxbSZ^KFMeHJVd'
    
    print(f"\n{'='*70}")
    print("VERIFICACIÓN DE CONTRASEÑA ESPECÍFICA")
    print(f"{'='*70}")
    print(f"Email: {SUPER_ADMIN_EMAIL}")
    print(f"Contraseña a verificar: {CONTRASEÑA_A_VERIFICAR}")
    print(f"{'='*70}\n")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Buscar el usuario
        cursor.execute("""
            SELECT id_usuario, email, password_hash, id_rol, activo
            FROM usuario 
            WHERE email = %s
        """, (SUPER_ADMIN_EMAIL,))
        
        usuario = cursor.fetchone()
        
        if not usuario:
            print(f"❌ ERROR: No se encontró el usuario con email {SUPER_ADMIN_EMAIL}")
            return False
        
        id_usuario, email_db, password_hash, id_rol, activo = usuario
        
        print(f"✅ Usuario encontrado:")
        print(f"   ID: {id_usuario}")
        print(f"   Email: {email_db}")
        print(f"   Rol: {id_rol}")
        print(f"   Activo: {activo}")
        print(f"\nHash almacenado: {password_hash[:60]}...")
        
        # Verificar contraseña
        print(f"\nVerificando contraseña...")
        try:
            password_valida = check_password_hash(password_hash, CONTRASEÑA_A_VERIFICAR)
            
            print(f"{'='*70}")
            if password_valida:
                print("✅ ¡CONTRASEÑA VÁLIDA!")
                print(f"   La contraseña '{CONTRASEÑA_A_VERIFICAR}' coincide con el hash almacenado.")
                print(f"   El login debería funcionar correctamente.")
            else:
                print("❌ CONTRASEÑA INVÁLIDA")
                print(f"   La contraseña '{CONTRASEÑA_A_VERIFICAR}' NO coincide con el hash almacenado.")
                print(f"\n   Posibles causas:")
                print(f"   1. La contraseña fue cambiada desde la interfaz web")
                print(f"   2. El hash está corrupto")
                print(f"   3. Hay espacios o caracteres especiales diferentes")
            print(f"{'='*70}\n")
            
            return password_valida
            
        except Exception as e:
            print(f"❌ ERROR al verificar contraseña: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return False
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    try:
        verificar_contraseña_especifica()
    except Exception as e:
        print(f"\n❌ ERROR CRÍTICO: {str(e)}")
        import traceback
        print(traceback.format_exc())

