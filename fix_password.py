#!/usr/bin/env python3
"""
Script para actualizar la contraseña del superadmin.
Evita el problema de scrypt en Python 3.9.6
"""
from werkzeug.security import generate_password_hash
from db_connector import get_db_connection
import os
from dotenv import load_dotenv

load_dotenv()

SUPER_ADMIN_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'admin@residencias.com')
SUPER_ADMIN_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', 'CambiarContraseña123!')

print(f"\n{'='*60}")
print("ACTUALIZANDO CONTRASEÑA DE SUPERADMIN")
print(f"{'='*60}")
print(f"Email: {SUPER_ADMIN_EMAIL}")
print(f"Nueva contraseña: {SUPER_ADMIN_PASSWORD}")
print(f"{'='*60}\n")

conn = get_db_connection()
cursor = conn.cursor()

try:
    # Buscar el superadmin
    cursor.execute("""
        SELECT id_usuario, email, id_rol
        FROM usuario 
        WHERE id_rol = 1 AND email = %s
    """, (SUPER_ADMIN_EMAIL,))
    
    usuario = cursor.fetchone()
    
    if not usuario:
        print(f"❌ ERROR: No se encontró el superadmin")
        exit(1)
    
    id_usuario, email_db, id_rol = usuario
    
    print(f"✅ Usuario encontrado:")
    print(f"   ID: {id_usuario}")
    print(f"   Email: {email_db}")
    print(f"   Rol: {id_rol}")
    
    # Generar nuevo hash usando pbkdf2 (más compatible)
    # Forzar método pbkdf2:sha256 en lugar de scrypt
    nuevo_password_hash = generate_password_hash(SUPER_ADMIN_PASSWORD, method='pbkdf2:sha256')
    
    # Actualizar contraseña
    cursor.execute("""
        UPDATE usuario 
        SET password_hash = %s,
            requiere_cambio_clave = TRUE
        WHERE id_usuario = %s
    """, (nuevo_password_hash, id_usuario))
    
    conn.commit()
    
    print(f"\n✅ Contraseña actualizada exitosamente")
    print(f"   Método de hash: pbkdf2:sha256 (compatible con Python 3.9.6)")
    print(f"   Nueva contraseña: {SUPER_ADMIN_PASSWORD}")
    print(f"   ⚠️  IMPORTANTE: Deberás cambiar la contraseña en el primer login")
    print(f"\n{'='*60}\n")
    
except Exception as e:
    conn.rollback()
    print(f"❌ ERROR: {str(e)}")
    import traceback
    traceback.print_exc()
    exit(1)
finally:
    cursor.close()
    conn.close()

