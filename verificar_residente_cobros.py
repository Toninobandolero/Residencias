import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2 import OperationalError

load_dotenv()

def verificar_residente_cobros():
    """Verifica si el residente de prueba cumple las condiciones para generar cobros previstos."""
    print("Verificando condiciones para cobros previstos...\n")
    
    db_host = os.getenv('DB_HOST')
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_port = os.getenv('DB_PORT', '5432')

    if not all([db_host, db_name, db_user, db_password]):
        print("❌ Error: Faltan variables de entorno requeridas")
        sys.exit(1)

    conn = None
    cursor = None
    try:
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port,
            connect_timeout=10
        )
        cursor = conn.cursor()
        
        # Obtener todos los residentes
        cursor.execute("""
            SELECT id_residente, id_residencia, nombre, apellido, activo, 
                   costo_habitacion, metodo_pago_preferido
            FROM residente
            ORDER BY id_residente
        """)
        
        residentes = cursor.fetchall()
        
        if not residentes:
            print("❌ No hay residentes registrados en la base de datos")
            return
        
        print(f"📋 Total de residentes: {len(residentes)}\n")
        
        for res in residentes:
            id_residente = res[0]
            id_residencia = res[1]
            nombre = res[2]
            apellido = res[3]
            activo = res[4]
            costo_habitacion = res[5]
            metodo_pago = res[6]
            
            print(f"👤 Residente: {nombre} {apellido} (ID: {id_residente})")
            print(f"   Residencia ID: {id_residencia}")
            print(f"   Activo: {'✅ Sí' if activo else '❌ No'}")
            print(f"   Costo Habitación: {'€' + str(costo_habitacion) if costo_habitacion else '❌ No definido'}")
            print(f"   Método Pago Preferido: {metodo_pago or 'No definido (usará transferencia por defecto)'}")
            
            # Verificar si cumple condiciones para generar cobro previsto
            puede_generar = True
            problemas = []
            
            if not activo:
                puede_generar = False
                problemas.append("❌ Residente no está activo")
            
            if not costo_habitacion or costo_habitacion <= 0:
                puede_generar = False
                problemas.append("❌ No tiene costo_habitacion definido o es 0")
            
            # Verificar si ya tiene cobros previstos
            cursor.execute("""
                SELECT COUNT(*) FROM pago_residente
                WHERE id_residente = %s 
                  AND id_residencia = %s
                  AND es_cobro_previsto = TRUE
            """, (id_residente, id_residencia))
            
            cobros_existentes = cursor.fetchone()[0]
            
            if puede_generar:
                print(f"   ✅ CUMPLE condiciones para generar cobro previsto")
                if cobros_existentes > 0:
                    print(f"   📊 Ya tiene {cobros_existentes} cobro(s) previsto(s) registrado(s)")
                    
                    # Mostrar detalles de los cobros previstos existentes
                    cursor.execute("""
                        SELECT id_pago, monto, fecha_prevista, mes_pagado, estado, concepto
                        FROM pago_residente
                        WHERE id_residente = %s 
                          AND id_residencia = %s
                          AND es_cobro_previsto = TRUE
                        ORDER BY fecha_prevista DESC
                    """, (id_residente, id_residencia))
                    
                    cobros = cursor.fetchall()
                    for cobro in cobros:
                        print(f"      - Cobro ID {cobro[0]}: €{cobro[1]} | Fecha: {cobro[2]} | Mes: {cobro[3]} | Estado: {cobro[4]} | {cobro[5]}")
                else:
                    print(f"   ⚠️  NO tiene cobros previstos registrados (se generará automáticamente al cargar Facturación)")
            else:
                print(f"   ❌ NO cumple condiciones para generar cobro previsto:")
                for problema in problemas:
                    print(f"      {problema}")
            
            print()  # Línea en blanco
        
        # Resumen
        print("=" * 60)
        print("📊 RESUMEN:")
        print("=" * 60)
        
        cursor.execute("""
            SELECT COUNT(*) FROM residente
            WHERE activo = TRUE 
              AND costo_habitacion IS NOT NULL 
              AND costo_habitacion > 0
        """)
        
        residentes_calificados = cursor.fetchone()[0]
        print(f"✅ Residentes que pueden generar cobros previstos: {residentes_calificados}")
        
        cursor.execute("""
            SELECT COUNT(*) FROM pago_residente
            WHERE es_cobro_previsto = TRUE
        """)
        
        cobros_totales = cursor.fetchone()[0]
        print(f"📋 Total de cobros previstos registrados: {cobros_totales}")
        
    except OperationalError as e:
        print(f"❌ Error de conexión a la base de datos: {e}")
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    verificar_residente_cobros()

