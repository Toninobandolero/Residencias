#!/usr/bin/env python3
"""
Script para inicializar permisos básicos del sistema en la tabla permiso.
"""
import os
from dotenv import load_dotenv

if os.path.exists('.env'):
    load_dotenv()

from db_connector import get_db_connection

def inicializar_permisos():
    """Inicializa los permisos básicos del sistema."""
    print("=" * 60)
    print("  INICIALIZANDO PERMISOS DEL SISTEMA")
    print("=" * 60)
    print()
    
    # Lista de permisos básicos del sistema
    permisos = [
        ("leer:residente", "Permite leer/listar residentes"),
        ("crear:residente", "Permite crear nuevos residentes"),
        ("editar:residente", "Permite editar residentes existentes"),
        ("eliminar:residente", "Permite eliminar residentes"),
        
        ("leer:personal", "Permite leer/listar personal"),
        ("crear:personal", "Permite crear nuevo personal"),
        ("editar:personal", "Permite editar personal existente"),
        ("eliminar:personal", "Permite eliminar personal"),
        
        ("leer:pago_residente", "Permite leer/listar pagos de residentes"),
        ("crear:pago_residente", "Permite crear pagos de residentes"),
        ("editar:pago_residente", "Permite editar pagos de residentes"),
        ("eliminar:pago_residente", "Permite eliminar pagos de residentes"),
        
        ("leer:pago_proveedor", "Permite leer/listar pagos a proveedores"),
        ("crear:pago_proveedor", "Permite crear pagos a proveedores"),
        ("editar:pago_proveedor", "Permite editar pagos a proveedores"),
        ("eliminar:pago_proveedor", "Permite eliminar pagos a proveedores"),
        
        ("leer:turno", "Permite leer/listar turnos"),
        ("crear:turno", "Permite crear turnos"),
        ("editar:turno", "Permite editar turnos"),
        ("eliminar:turno", "Permite eliminar turnos"),
        
        ("leer:registro_asistencial", "Permite leer/listar registros asistenciales"),
        ("crear:registro_asistencial", "Permite crear registros asistenciales"),
        ("editar:registro_asistencial", "Permite editar registros asistenciales"),
        ("eliminar:registro_asistencial", "Permite eliminar registros asistenciales"),
        
        ("leer:tratamiento", "Permite leer/listar tratamientos médicos"),
        ("crear:tratamiento", "Permite crear tratamientos médicos"),
        ("editar:tratamiento", "Permite editar tratamientos médicos"),
        ("eliminar:tratamiento", "Permite eliminar tratamientos médicos"),
        
        ("crear:usuario", "Permite crear nuevos usuarios"),
        ("editar:usuario", "Permite editar usuarios existentes"),
        ("eliminar:usuario", "Permite eliminar usuarios"),
        ("leer:usuario", "Permite leer/listar usuarios"),
        
        ("leer:residencia", "Permite leer/listar residencias"),
        ("editar:residencia", "Permite editar información de residencias"),
        
        ("leer:documento", "Permite leer/listar documentos"),
        ("crear:documento", "Permite crear/subir documentos"),
        ("eliminar:documento", "Permite eliminar documentos"),
        
        ("leer:cobro", "Permite leer/listar cobros de residentes"),
        ("crear:cobro", "Permite crear nuevos cobros"),
        ("editar:cobro", "Permite editar cobros existentes"),
        ("eliminar:cobro", "Permite eliminar cobros"),
        
        ("leer:proveedor", "Permite leer/listar proveedores"),
        ("crear:proveedor", "Permite crear nuevos proveedores"),
        ("editar:proveedor", "Permite editar proveedores existentes"),
        ("eliminar:proveedor", "Permite eliminar proveedores"),
        ("escribir:proveedor", "Permite crear y editar proveedores"),
        
        ("leer:receiver", "Permite leer/listar entidades fiscales (receiver)"),
        ("escribir:receiver", "Permite crear y modificar entidades fiscales (receiver)"),
        
        ("escribir:pago_proveedor", "Permite crear y editar pagos a proveedores"),
        ("escribir:residencia", "Permite editar información de residencias"),
    ]
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print(f"Creando {len(permisos)} permisos...")
        print()
        
        creados = 0
        existentes = 0
        
        for nombre_permiso, descripcion in permisos:
            cursor.execute("""
                INSERT INTO permiso (nombre_permiso, descripcion, activo)
                VALUES (%s, %s, TRUE)
                ON CONFLICT (nombre_permiso) DO UPDATE
                SET descripcion = EXCLUDED.descripcion,
                    activo = TRUE
                RETURNING nombre_permiso
            """, (nombre_permiso, descripcion))
            
            resultado = cursor.fetchone()
            if resultado:
                if cursor.rowcount > 0:
                    print(f"  ✅ {nombre_permiso}")
                    creados += 1
                else:
                    print(f"  ⚠️  {nombre_permiso} (ya existía)")
                    existentes += 1
        
        conn.commit()
        
        print()
        print("=" * 60)
        print("  ✅ PROCESO COMPLETADO")
        print("=" * 60)
        print(f"Permisos creados: {creados}")
        print(f"Permisos ya existentes: {existentes}")
        print(f"Total: {len(permisos)}")
        print()
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == '__main__':
    inicializar_permisos()
