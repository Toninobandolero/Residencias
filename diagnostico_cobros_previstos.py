"""
Script de diagnóstico para verificar por qué algunos residentes no tienen cobros previstos.
"""
import os
import sys
from dotenv import load_dotenv
import psycopg2
from datetime import datetime, timedelta

load_dotenv()

def diagnostico_cobros_previstos():
    """Diagnostica por qué algunos residentes no tienen cobros previstos."""
    print("🔍 DIAGNÓSTICO: Cobros Previstos")
    print("=" * 80)
    
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
        
        # Calcular mes siguiente
        hoy = datetime.now()
        mes_actual = hoy.month
        año_actual = hoy.year
        
        if mes_actual == 12:
            siguiente_mes = datetime(año_actual + 1, 1, 1)
        else:
            siguiente_mes = datetime(año_actual, mes_actual + 1, 1)
        
        mes_siguiente = siguiente_mes.strftime('%Y-%m')
        
        print(f"📅 Fecha actual: {hoy.strftime('%Y-%m-%d')}")
        print(f"📅 Mes siguiente: {mes_siguiente}\n")
        
        # 1. Obtener TODOS los residentes (activos e inactivos)
        print("1️⃣ TODOS LOS RESIDENTES:")
        print("-" * 80)
        cursor.execute("""
            SELECT id_residente, nombre, apellido, id_residencia, activo, 
                   costo_habitacion, fecha_ingreso, metodo_pago_preferido
            FROM residente
            ORDER BY id_residencia, id_residente
        """)
        
        todos_residentes = cursor.fetchall()
        print(f"   Total de residentes en BD: {len(todos_residentes)}\n")
        
        for res in todos_residentes:
            id_res, nombre, apellido, id_resid, activo, costo, fecha_ing, metodo = res
            estado = "✅ Activo" if activo else "❌ Inactivo"
            costo_str = f"€{costo}" if costo else "❌ Sin costo"
            fecha_str = fecha_ing.strftime('%Y-%m-%d') if fecha_ing else "❌ Sin fecha"
            metodo_str = metodo or "transferencia (por defecto)"
            
            print(f"   👤 {nombre} {apellido} (ID: {id_res}, Residencia: {id_resid})")
            print(f"      Estado: {estado}")
            print(f"      Costo habitación: {costo_str}")
            print(f"      Fecha ingreso: {fecha_str}")
            print(f"      Método pago: {metodo_str}")
            print()
        
        # 2. Obtener residentes que CUMPLEN condiciones para cobros previstos
        print("\n2️⃣ RESIDENTES QUE CUMPLEN CONDICIONES PARA COBROS PREVISTOS:")
        print("-" * 80)
        cursor.execute("""
            SELECT id_residente, nombre, apellido, id_residencia, costo_habitacion, 
                   fecha_ingreso, metodo_pago_preferido
            FROM residente
            WHERE activo = TRUE 
              AND costo_habitacion IS NOT NULL 
              AND costo_habitacion > 0
              AND fecha_ingreso IS NOT NULL
            ORDER BY id_residencia, id_residente
        """)
        
        residentes_candidatos = cursor.fetchall()
        print(f"   Total de candidatos: {len(residentes_candidatos)}\n")
        
        for res in residentes_candidatos:
            id_res, nombre, apellido, id_resid, costo, fecha_ing, metodo = res
            print(f"   ✅ {nombre} {apellido} (ID: {id_res})")
            print(f"      Residencia: {id_resid}")
            print(f"      Costo: €{costo}")
            print(f"      Fecha ingreso: {fecha_ing.strftime('%Y-%m-%d')}")
            print(f"      Método pago: {metodo or 'transferencia (por defecto)'}")
            print()
        
        # 3. Verificar cobros completados para el mes siguiente
        print("\n3️⃣ COBROS COMPLETADOS PARA EL MES SIGUIENTE:")
        print("-" * 80)
        cursor.execute("""
            SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                   p.mes_pagado, p.estado, p.monto
            FROM pago_residente p
            JOIN residente r ON p.id_residente = r.id_residente
            WHERE p.mes_pagado = %s
              AND p.estado = 'cobrado'
            ORDER BY p.id_residente
        """, (mes_siguiente,))
        
        cobros_completados = cursor.fetchall()
        print(f"   Total de cobros completados para {mes_siguiente}: {len(cobros_completados)}\n")
        
        if cobros_completados:
            for cobro in cobros_completados:
                id_pago, id_res, nombre, mes_pag, estado, monto = cobro
                print(f"   ✅ {nombre} (ID Residente: {id_res})")
                print(f"      Mes pagado: {mes_pag}")
                print(f"      Monto: €{monto}")
                print()
        else:
            print("   ℹ️  No hay cobros completados para este mes\n")
        
        # 4. Verificar cobros previstos existentes
        print("\n4️⃣ COBROS PREVISTOS EXISTENTES:")
        print("-" * 80)
        cursor.execute("""
            SELECT p.id_pago, p.id_residente, r.nombre || ' ' || r.apellido as residente,
                   p.mes_pagado, p.estado, p.monto, p.fecha_prevista, p.concepto
            FROM pago_residente p
            JOIN residente r ON p.id_residente = r.id_residente
            WHERE p.es_cobro_previsto = TRUE
              AND p.estado = 'pendiente'
            ORDER BY p.id_residente
        """)
        
        cobros_previstos = cursor.fetchall()
        print(f"   Total de cobros previstos pendientes: {len(cobros_previstos)}\n")
        
        if cobros_previstos:
            for cobro in cobros_previstos:
                id_pago, id_res, nombre, mes_pag, estado, monto, fecha_prev, concepto = cobro
                fecha_str = fecha_prev.strftime('%Y-%m-%d') if fecha_prev else "N/A"
                print(f"   📋 {nombre} (ID Residente: {id_res})")
                print(f"      Concepto: {concepto}")
                print(f"      Mes pagado: {mes_pag}")
                print(f"      Monto: €{monto}")
                print(f"      Fecha prevista: {fecha_str}")
                print()
        else:
            print("   ℹ️  No hay cobros previstos pendientes\n")
        
        # 5. Análisis: qué residentes deberían tener cobro pero no lo tienen
        print("\n5️⃣ ANÁLISIS: RESIDENTES QUE DEBERÍAN TENER COBRO PREVISTO:")
        print("-" * 80)
        
        # Obtener IDs de residentes que ya tienen cobro previsto
        cursor.execute("""
            SELECT DISTINCT id_residente
            FROM pago_residente
            WHERE es_cobro_previsto = TRUE
              AND estado = 'pendiente'
        """)
        ids_con_cobro_previsto = {row[0] for row in cursor.fetchall()}
        
        # Obtener IDs de residentes que ya tienen cobro completado
        cursor.execute("""
            SELECT DISTINCT id_residente
            FROM pago_residente
            WHERE mes_pagado = %s
              AND estado = 'cobrado'
        """, (mes_siguiente,))
        ids_con_cobro_completado = {row[0] for row in cursor.fetchall()}
        
        residentes_sin_cobro = []
        for res in residentes_candidatos:
            id_res = res[0]
            nombre = res[1]
            apellido = res[2]
            
            if id_res not in ids_con_cobro_previsto and id_res not in ids_con_cobro_completado:
                residentes_sin_cobro.append((id_res, nombre, apellido, res[3], res[4], res[5], res[6]))
        
        print(f"   Total de residentes que DEBERÍAN tener cobro pero NO lo tienen: {len(residentes_sin_cobro)}\n")
        
        if residentes_sin_cobro:
            print("   ⚠️  RESIDENTES FALTANTES:")
            for id_res, nombre, apellido, id_resid, costo, fecha_ing, metodo in residentes_sin_cobro:
                print(f"   ❌ {nombre} {apellido} (ID: {id_res}, Residencia: {id_resid})")
                print(f"      Costo: €{costo}")
                print(f"      Fecha ingreso: {fecha_ing.strftime('%Y-%m-%d')}")
                print(f"      Método pago: {metodo or 'transferencia (por defecto)'}")
                print()
        else:
            print("   ✅ Todos los residentes candidatos tienen cobro previsto o completado\n")
        
        # 6. Resumen final
        print("\n" + "=" * 80)
        print("📊 RESUMEN FINAL:")
        print("-" * 80)
        print(f"   Total residentes en BD: {len(todos_residentes)}")
        print(f"   Residentes activos candidatos: {len(residentes_candidatos)}")
        print(f"   Cobros previstos existentes: {len(cobros_previstos)}")
        print(f"   Cobros completados para {mes_siguiente}: {len(cobros_completados)}")
        print(f"   Residentes sin cobro previsto: {len(residentes_sin_cobro)}")
        print()
        
        if len(residentes_sin_cobro) > 0:
            print("   ⚠️  CONCLUSIÓN: Hay residentes que deberían tener cobro previsto pero no lo tienen.")
            print("      Se recomienda regenerar los cobros previstos.")
        else:
            print("   ✅ CONCLUSIÓN: Todos los residentes candidatos tienen cobro previsto o completado.")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    diagnostico_cobros_previstos()

