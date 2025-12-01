"""
Script para verificar usuarios existentes en el sistema.
"""
from db_connector import get_db_connection

try:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    print("\n" + "="*60)
    print("USUARIOS EN EL SISTEMA")
    print("="*60)
    
    cursor.execute("""
        SELECT u.id_usuario, u.email, u.id_rol, r.nombre as nombre_rol, 
               u.requiere_cambio_clave, u.id_residencia
        FROM usuario u
        LEFT JOIN rol r ON u.id_rol = r.id_rol
        ORDER BY u.id_usuario
    """)
    
    usuarios = cursor.fetchall()
    
    if not usuarios:
        print("⚠️  No hay usuarios en el sistema")
    else:
        print(f"\nTotal: {len(usuarios)} usuario(s)\n")
        for u in usuarios:
            print(f"ID: {u[0]}")
            print(f"  Email: {u[1]}")
            print(f"  Rol: {u[3]} (id_rol={u[2]})")
            print(f"  Requiere cambio de clave: {'Sí' if u[4] else 'No'}")
            print(f"  id_residencia: {u[5] if u[5] else 'NULL (acceso total)'}")
            print()
    
    print("="*60)
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"Error: {str(e)}")

