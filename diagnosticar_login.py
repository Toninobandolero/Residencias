"""
Script de diagnóstico para problemas de login.
Verifica el estado del usuario superadmin en la base de datos.
"""
from werkzeug.security import check_password_hash, generate_password_hash
from db_connector import get_db_connection
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def diagnosticar_login():
    """
    Diagnostica problemas de login del superadmin.
    """
    SUPER_ADMIN_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'admin@residencias.com')
    SUPER_ADMIN_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', 'CambiarContraseña123!')
    
    print(f"\n{'='*70}")
    print("DIAGNÓSTICO DE LOGIN - SUPERADMIN")
    print(f"{'='*70}")
    print(f"Email configurado: {SUPER_ADMIN_EMAIL}")
    print(f"Contraseña configurada: {SUPER_ADMIN_PASSWORD}")
    print(f"{'='*70}\n")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Buscar el usuario por email
        print("1. Buscando usuario en la base de datos...")
        cursor.execute("""
            SELECT id_usuario, email, password_hash, id_rol, activo, requiere_cambio_clave, nombre, apellido
            FROM usuario 
            WHERE email = %s
        """, (SUPER_ADMIN_EMAIL,))
        
        usuario = cursor.fetchone()
        
        if not usuario:
            print(f"   ❌ ERROR: No se encontró ningún usuario con email '{SUPER_ADMIN_EMAIL}'")
            print(f"\n   Buscando usuarios con rol super_admin (id_rol = 1)...")
            cursor.execute("""
                SELECT id_usuario, email, id_rol, activo
                FROM usuario 
                WHERE id_rol = 1
            """)
            superadmins = cursor.fetchall()
            if superadmins:
                print(f"   Se encontraron {len(superadmins)} usuario(s) con rol super_admin:")
                for sa in superadmins:
                    print(f"      - ID: {sa[0]}, Email: {sa[1]}, Activo: {sa[3]}")
            else:
                print(f"   ❌ No se encontraron usuarios con rol super_admin")
            return False
        
        id_usuario, email_db, password_hash, id_rol, activo, requiere_cambio_clave, nombre, apellido = usuario
        
        print(f"   ✅ Usuario encontrado:")
        print(f"      ID: {id_usuario}")
        print(f"      Email: {email_db}")
        print(f"      Nombre: {nombre or 'N/A'}")
        print(f"      Apellido: {apellido or 'N/A'}")
        print(f"      Rol ID: {id_rol}")
        print(f"      Activo: {activo}")
        print(f"      Requiere cambio de clave: {requiere_cambio_clave}")
        
        # 2. Verificar que sea super_admin
        print(f"\n2. Verificando rol...")
        if id_rol != 1:
            print(f"   ⚠️  ADVERTENCIA: El usuario NO es super_admin (id_rol = {id_rol}, debería ser 1)")
        else:
            print(f"   ✅ El usuario es super_admin (id_rol = 1)")
        
        # 3. Verificar que esté activo
        print(f"\n3. Verificando estado activo...")
        if not activo:
            print(f"   ❌ ERROR: El usuario está INACTIVO")
            print(f"   Esto impedirá el login. Debes activarlo primero.")
        else:
            print(f"   ✅ El usuario está activo")
        
        # 4. Verificar contraseña
        print(f"\n4. Verificando contraseña...")
        print(f"   Contraseña a verificar: '{SUPER_ADMIN_PASSWORD}'")
        print(f"   Hash almacenado: {password_hash[:50]}...")
        
        try:
            password_valida = check_password_hash(password_hash, SUPER_ADMIN_PASSWORD)
            print(f"   Resultado de verificación: {password_valida}")
            
            if password_valida:
                print(f"   ✅ CONTRASEÑA VÁLIDA - El login debería funcionar")
            else:
                print(f"   ❌ CONTRASEÑA INVÁLIDA - El hash no coincide con la contraseña")
                print(f"\n   Probando con diferentes variaciones...")
                
                # Probar variaciones comunes
                variaciones = [
                    SUPER_ADMIN_PASSWORD.strip(),
                    SUPER_ADMIN_PASSWORD.lower(),
                    SUPER_ADMIN_PASSWORD.upper(),
                    'CambiarContraseña123!',
                    'CambiarContraseña123',
                ]
                
                for var in variaciones:
                    if check_password_hash(password_hash, var):
                        print(f"   ✅ ¡ENCONTRADA! La contraseña correcta es: '{var}'")
                        break
                else:
                    print(f"   ❌ Ninguna variación funcionó")
                    print(f"\n   💡 SOLUCIÓN: Resetea la contraseña ejecutando:")
                    print(f"      python reset_superadmin_password.py reset")
        except Exception as e:
            print(f"   ❌ ERROR al verificar contraseña: {str(e)}")
            import traceback
            print(traceback.format_exc())
        
        # 5. Verificar residencias asignadas
        print(f"\n5. Verificando residencias asignadas...")
        try:
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public'
                    AND table_name = 'usuario_residencia'
                )
            """)
            tabla_existe = cursor.fetchone()[0]
            
            if tabla_existe:
                cursor.execute("""
                    SELECT ur.id_residencia, res.nombre
                    FROM usuario_residencia ur
                    JOIN residencia res ON ur.id_residencia = res.id_residencia
                    WHERE ur.id_usuario = %s
                """, (id_usuario,))
                residencias = cursor.fetchall()
                if residencias:
                    print(f"   Residencias asignadas: {len(residencias)}")
                    for r in residencias:
                        print(f"      - {r[1]} (ID: {r[0]})")
                else:
                    print(f"   ⚠️  No hay residencias asignadas (esto es normal para super_admin)")
            else:
                print(f"   ⚠️  Tabla usuario_residencia no existe (modo legacy)")
                cursor.execute("SELECT id_residencia FROM usuario WHERE id_usuario = %s", (id_usuario,))
                res = cursor.fetchone()
                if res and res[0]:
                    print(f"   Residencia (legacy): ID {res[0]}")
                else:
                    print(f"   No hay residencia asignada (normal para super_admin)")
        except Exception as e:
            print(f"   ⚠️  Error al verificar residencias: {str(e)}")
        
        # 6. Resumen y recomendaciones
        print(f"\n{'='*70}")
        print("RESUMEN Y RECOMENDACIONES")
        print(f"{'='*70}")
        
        problemas = []
        if id_rol != 1:
            problemas.append("El usuario no es super_admin")
        if not activo:
            problemas.append("El usuario está inactivo")
        if not password_valida:
            problemas.append("La contraseña no coincide")
        
        if problemas:
            print(f"❌ PROBLEMAS ENCONTRADOS:")
            for p in problemas:
                print(f"   - {p}")
            print(f"\n💡 SOLUCIONES:")
            if not activo:
                print(f"   1. Activa el usuario ejecutando:")
                print(f"      UPDATE usuario SET activo = TRUE WHERE id_usuario = {id_usuario};")
            if not password_valida:
                print(f"   2. Resetea la contraseña ejecutando:")
                print(f"      python reset_superadmin_password.py reset")
        else:
            print(f"✅ TODO PARECE ESTAR BIEN")
            print(f"   El login debería funcionar correctamente.")
            print(f"\n   Si aún así no funciona, verifica:")
            print(f"   - Que el servidor Flask esté corriendo")
            print(f"   - Que la conexión a la base de datos funcione")
            print(f"   - Los logs del servidor para ver errores específicos")
        
        print(f"{'='*70}\n")
        
        return len(problemas) == 0
        
    except Exception as e:
        print(f"❌ ERROR durante el diagnóstico: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    diagnosticar_login()

