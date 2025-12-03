"""
Script para diagnosticar y corregir los cobros de Miguel Hernández.
"""
from db_connector import get_db_connection
from datetime import datetime, timedelta
from app import generar_cobros_historicos_completados

def diagnosticar_miguel():
    """
    Diagnostica los cobros de Miguel Hernández y regenera los que falten.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        print("\n" + "="*70)
        print("DIAGNÓSTICO DE COBROS - MIGUEL HERNÁNDEZ")
        print("="*70 + "\n")
        
        # Buscar a Miguel Hernández
        cursor.execute("""
            SELECT id_residente, nombre, apellido, fecha_ingreso, costo_habitacion, 
                   metodo_pago_preferido, id_residencia
            FROM residente
            WHERE LOWER(nombre) LIKE '%miguel%' AND LOWER(apellido) LIKE '%hernandez%'
               OR LOWER(nombre) LIKE '%miguel%' AND LOWER(apellido) LIKE '%hernández%'
        """)
        
        miguel = cursor.fetchone()
        
        if not miguel:
            print("❌ No se encontró a Miguel Hernández en la base de datos")
            return
        
        id_residente, nombre, apellido, fecha_ingreso, costo_habitacion, metodo_pago, id_residencia = miguel
        
        print(f"✅ Residente encontrado:")
        print(f"   ID: {id_residente}")
        print(f"   Nombre: {nombre} {apellido}")
        print(f"   Fecha de ingreso: {fecha_ingreso}")
        print(f"   Costo habitación: {costo_habitacion}€")
        print(f"   Método de pago: {metodo_pago}")
        print(f"   ID Residencia: {id_residencia}\n")
        
        # Verificar cobros existentes
        cursor.execute("""
            SELECT id_pago, mes_pagado, concepto, estado, fecha_pago, fecha_prevista, monto
            FROM pago_residente
            WHERE id_residente = %s
            ORDER BY mes_pagado, fecha_pago
        """, (id_residente,))
        
        cobros_existentes = cursor.fetchall()
        
        print(f"📋 Cobros existentes ({len(cobros_existentes)}):")
        for cobro in cobros_existentes:
            id_pago, mes_pagado, concepto, estado, fecha_pago, fecha_prevista, monto = cobro
            print(f"   - {concepto} ({mes_pagado}): {estado}, Monto: {monto}€, Fecha: {fecha_pago}")
        
        # Verificar específicamente diciembre 2025
        cursor.execute("""
            SELECT id_pago, mes_pagado, concepto, estado, fecha_pago, monto
            FROM pago_residente
            WHERE id_residente = %s
              AND mes_pagado = '2025-12'
              AND concepto ILIKE 'diciembre%'
        """, (id_residente,))
        
        diciembre_cobros = cursor.fetchall()
        
        print(f"\n🔍 Cobros de Diciembre 2025 ({len(diciembre_cobros)}):")
        if diciembre_cobros:
            for cobro in diciembre_cobros:
                id_pago, mes_pagado, concepto, estado, fecha_pago, monto = cobro
                print(f"   - ID: {id_pago}, {concepto}: {estado}, Fecha: {fecha_pago}, Monto: {monto}€")
        else:
            print("   ❌ NO HAY COBROS DE DICIEMBRE 2025")
        
        # Calcular qué cobros deberían existir
        if fecha_ingreso and costo_habitacion and costo_habitacion > 0:
            hoy = datetime.now().date()
            mes_actual = datetime(hoy.year, hoy.month, 1).date()
            
            # Mes de ingreso
            if isinstance(fecha_ingreso, str):
                fecha_ingreso = datetime.strptime(fecha_ingreso, '%Y-%m-%d').date()
            
            mes_ingreso = datetime(fecha_ingreso.year, fecha_ingreso.month, 1).date()
            
            print(f"\n📅 Análisis de fechas:")
            print(f"   Fecha de ingreso: {fecha_ingreso}")
            print(f"   Mes de ingreso: {mes_ingreso}")
            print(f"   Mes actual: {mes_actual}")
            
            # Generar lista de meses que deberían tener cobros
            meses_esperados = []
            fecha_actual = mes_ingreso
            while fecha_actual < mes_actual:
                meses_esperados.append(fecha_actual.strftime('%Y-%m'))
                if fecha_actual.month == 12:
                    fecha_actual = datetime(fecha_actual.year + 1, 1, 1).date()
                else:
                    fecha_actual = datetime(fecha_actual.year, fecha_actual.month + 1, 1).date()
            
            print(f"\n📊 Meses que deberían tener cobros completados ({len(meses_esperados)}):")
            for mes in meses_esperados:
                # Verificar si existe
                cursor.execute("""
                    SELECT id_pago, estado, concepto
                    FROM pago_residente
                    WHERE id_residente = %s
                      AND mes_pagado = %s
                      AND estado = 'cobrado'
                """, (id_residente, mes))
                existe = cursor.fetchone()
                if existe:
                    print(f"   ✅ {mes}: Existe (ID: {existe[0]}, {existe[2]})")
                else:
                    print(f"   ❌ {mes}: FALTA")
            
            # Verificar específicamente diciembre 2025
            if '2025-12' in meses_esperados:
                print(f"\n⚠️  Diciembre 2025 DEBERÍA tener un cobro completado")
                cursor.execute("""
                    SELECT id_pago, estado, concepto, fecha_pago
                    FROM pago_residente
                    WHERE id_residente = %s
                      AND mes_pagado = '2025-12'
                """, (id_residente,))
                diciembre = cursor.fetchone()
                if not diciembre:
                    print("   ❌ NO EXISTE - Regenerando...")
                    # Regenerar cobros históricos
                    cobros_generados = generar_cobros_historicos_completados(
                        cursor, id_residente, id_residencia, fecha_ingreso, costo_habitacion, metodo_pago or 'transferencia'
                    )
                    conn.commit()
                    print(f"   ✅ Generados {cobros_generados} cobros históricos")
                    
                    # Verificar nuevamente diciembre
                    cursor.execute("""
                        SELECT id_pago, estado, concepto, fecha_pago, monto
                        FROM pago_residente
                        WHERE id_residente = %s
                          AND mes_pagado = '2025-12'
                          AND concepto ILIKE 'diciembre%'
                    """, (id_residente,))
                    diciembre_nuevo = cursor.fetchone()
                    if diciembre_nuevo:
                        print(f"   ✅ Cobro de diciembre creado: ID {diciembre_nuevo[0]}, {diciembre_nuevo[2]}, {diciembre_nuevo[4]}€")
                    else:
                        print("   ⚠️  Aún no se generó el cobro de diciembre")
                else:
                    print(f"   ✅ Existe: ID {diciembre[0]}, Estado: {diciembre[1]}, Concepto: {diciembre[2]}")
            else:
                print(f"\n⚠️  Diciembre 2025 NO está en el rango esperado (mes actual o futuro)")
        
        print("\n" + "="*70 + "\n")
        
    except Exception as e:
        conn.rollback()
        print(f"❌ ERROR: {str(e)}")
        import traceback
        print(traceback.format_exc())
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    diagnosticar_miguel()

