import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2 import OperationalError
from datetime import datetime, timedelta

load_dotenv()

def diagnostico_generar_cobros():
    """Diagnóstico detallado de por qué no se generan cobros previstos."""
    print("🔍 DIAGNÓSTICO: Generación de Cobros Previstos\n")
    print("=" * 60)
    
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
        
        # Calcular mes siguiente (igual que en el backend)
        hoy = datetime.now()
        if hoy.month == 12:
            fecha_base = datetime(hoy.year + 1, 1, 1)
        else:
            fecha_base = datetime(hoy.year, hoy.month + 1, 1)
        
        mes_pagado = fecha_base.strftime('%Y-%m')
        print(f"📅 Mes de referencia: {mes_pagado}")
        print(f"📅 Fecha base: {fecha_base.strftime('%Y-%m-%d')}\n")
        
        # Verificar residentes que deberían generar cobros
        print("1️⃣ Verificando residentes que deberían generar cobros...")
        cursor.execute("""
            SELECT id_residente, nombre, apellido, activo, costo_habitacion, metodo_pago_preferido, id_residencia
            FROM residente
            WHERE activo = TRUE 
              AND costo_habitacion IS NOT NULL 
              AND costo_habitacion > 0
            ORDER BY id_residente
        """)
        
        residentes = cursor.fetchall()
        print(f"   ✅ Residentes encontrados: {len(residentes)}\n")
        
        if not residentes:
            print("❌ No hay residentes que cumplan las condiciones")
            return
        
        for res in residentes:
            id_residente = res[0]
            nombre = res[1]
            apellido = res[2]
            activo = res[3]
            costo_habitacion = res[4]
            metodo_pago = res[5] or 'transferencia'
            id_residencia = res[6]
            
            print(f"   👤 {nombre} {apellido} (ID: {id_residente}, Residencia: {id_residencia})")
            print(f"      - Activo: {activo}")
            print(f"      - Costo: €{costo_habitacion}")
            print(f"      - Método pago: {metodo_pago}")
            
            # Calcular fecha prevista - todos los métodos usan el día 1 del mes que se va a cobrar
            # fecha_base ya es el día 1 del mes siguiente, así que lo usamos directamente
            fecha_prevista = fecha_base
            
            print(f"      - Fecha prevista calculada: {fecha_prevista.strftime('%Y-%m-%d')}")
            
            # Verificar si ya existe un cobro previsto
            cursor.execute("""
                SELECT id_pago, monto, fecha_prevista, mes_pagado, estado, concepto
                FROM pago_residente
                WHERE id_residente = %s 
                  AND id_residencia = %s
                  AND es_cobro_previsto = TRUE
                  AND mes_pagado = %s
            """, (id_residente, id_residencia, mes_pagado))
            
            cobro_existente = cursor.fetchone()
            
            if cobro_existente:
                print(f"      ⚠️  YA EXISTE un cobro previsto para este mes:")
                print(f"         - ID: {cobro_existente[0]}")
                print(f"         - Monto: €{cobro_existente[1]}")
                print(f"         - Fecha prevista: {cobro_existente[2]}")
                print(f"         - Mes pagado: {cobro_existente[3]}")
                print(f"         - Estado: {cobro_existente[4]}")
                print(f"         - Concepto: {cobro_existente[5]}")
                print(f"      ❌ Por eso NO se genera uno nuevo (evita duplicados)")
            else:
                print(f"      ✅ NO existe cobro previsto para este mes")
                print(f"      ✅ Se DEBERÍA generar uno nuevo")
                
                # Intentar insertar manualmente para ver si hay error
                try:
                    cursor.execute("""
                        INSERT INTO pago_residente (
                            id_residente, id_residencia, monto, fecha_prevista,
                            mes_pagado, concepto, metodo_pago, estado, es_cobro_previsto
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id_pago
                    """, (
                        id_residente,
                        id_residencia,
                        costo_habitacion,
                        fecha_prevista.date(),
                        mes_pagado,
                        f"Pago mensual habitación - {nombre} {apellido}",
                        metodo_pago,
                        'pendiente',
                        True
                    ))
                    
                    id_pago_generado = cursor.fetchone()[0]
                    conn.commit()
                    print(f"      ✅✅ COBRO GENERADO EXITOSAMENTE (ID: {id_pago_generado})")
                except Exception as e:
                    conn.rollback()
                    print(f"      ❌ ERROR al intentar generar: {str(e)}")
            
            print()
        
        # Resumen de cobros previstos existentes
        print("2️⃣ Cobros previstos existentes en la base de datos:")
        cursor.execute("""
            SELECT id_pago, id_residente, r.nombre || ' ' || r.apellido as residente,
                   monto, fecha_prevista, mes_pagado, estado, concepto
            FROM pago_residente p
            JOIN residente r ON p.id_residente = r.id_residente
            WHERE p.es_cobro_previsto = TRUE
            ORDER BY fecha_prevista DESC
        """)
        
        cobros = cursor.fetchall()
        if cobros:
            for cobro in cobros:
                print(f"   - ID {cobro[0]}: {cobro[2]} | €{cobro[3]} | Fecha: {cobro[4]} | Mes: {cobro[5]} | Estado: {cobro[6]}")
        else:
            print("   (No hay cobros previstos registrados)")
        
        print("\n" + "=" * 60)
        print("✅ Diagnóstico completado")
        
    except OperationalError as e:
        print(f"❌ Error de conexión: {e}")
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    diagnostico_generar_cobros()

