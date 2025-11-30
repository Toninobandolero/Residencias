"""
Script para regenerar los cobros previstos directamente desde la base de datos.
No requiere autenticación HTTP, se conecta directamente a PostgreSQL.
"""
import os
import sys
from dotenv import load_dotenv
import psycopg2
from datetime import datetime, timedelta

load_dotenv()

def regenerar_cobros_previstos():
    """Regenera los cobros previstos directamente desde la base de datos."""
    print("🔄 Regenerando cobros previstos directamente desde la BD...")
    print("=" * 60)
    
    db_host = os.getenv('DB_HOST')
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_port = os.getenv('DB_PORT', '5432')
    id_residencia = int(os.getenv('ID_RESIDENCIA', '1'))  # Por defecto Violetas 1
    
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
        
        print(f"📅 Mes siguiente: {mes_siguiente}")
        print(f"📅 Residencia: {id_residencia}\n")
        
        # Limpiar TODOS los cobros previstos pendientes
        print("1️⃣ Limpiando cobros previstos existentes...")
        cursor.execute("""
            DELETE FROM pago_residente
            WHERE id_residencia = %s
              AND es_cobro_previsto = TRUE
              AND estado = 'pendiente'
        """, (id_residencia,))
        
        cobros_eliminados = cursor.rowcount
        print(f"   ✅ Cobros eliminados: {cobros_eliminados}\n")
        
        # Obtener todos los residentes activos
        print("2️⃣ Obteniendo residentes activos...")
        cursor.execute("""
            SELECT id_residente, nombre, apellido, costo_habitacion, metodo_pago_preferido, fecha_ingreso
            FROM residente
            WHERE id_residencia = %s 
              AND activo = TRUE 
              AND costo_habitacion IS NOT NULL 
              AND costo_habitacion > 0
              AND fecha_ingreso IS NOT NULL
        """, (id_residencia,))
        
        residentes = cursor.fetchall()
        print(f"   ✅ Residentes encontrados: {len(residentes)}\n")
        
        if not residentes:
            print("❌ No hay residentes que cumplan las condiciones")
            conn.rollback()
            return
        
        # Generar cobros previstos
        print("3️⃣ Generando cobros previstos...")
        cobros_generados = 0
        cobros_duplicados = 0
        errores = []
        
        meses_espanol = {
            1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril',
            5: 'mayo', 6: 'junio', 7: 'julio', 8: 'agosto',
            9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'
        }
        
        for residente in residentes:
            id_residente = residente[0]
            nombre = residente[1]
            apellido = residente[2]
            costo_habitacion = float(residente[3])
            metodo_pago = residente[4] or 'transferencia'
            fecha_ingreso = residente[5]
            
            # Verificar si ya tiene cobro completado para este mes
            cursor.execute("""
                SELECT id_pago FROM pago_residente
                WHERE id_residente = %s 
                  AND id_residencia = %s
                  AND mes_pagado = %s
                  AND estado = 'cobrado'
            """, (id_residente, id_residencia, mes_siguiente))
            
            if cursor.fetchone():
                cobros_duplicados += 1
                print(f"   ⏭️  {nombre} {apellido}: Ya tiene cobro completado para {mes_siguiente}")
                continue
            
            # Calcular fecha prevista según método de pago
            if metodo_pago.lower() in ['remesa']:
                ultimo_dia = (siguiente_mes - timedelta(days=1)).day
                dia_remesa = min(30, ultimo_dia)
                fecha_prevista = datetime(año_actual, mes_actual, dia_remesa)
                mes_pagado = mes_siguiente
            elif metodo_pago.lower() in ['transferencia', 'transfer']:
                fecha_prevista = datetime(siguiente_mes.year, siguiente_mes.month, 3)
                mes_pagado = mes_siguiente
            else:
                fecha_prevista = datetime(siguiente_mes.year, siguiente_mes.month, 5)
                mes_pagado = mes_siguiente
            
            nombre_mes = meses_espanol.get(siguiente_mes.month, 'mes')
            concepto = f"Pago {nombre_mes}"
            
            # Crear el cobro previsto
            try:
                cursor.execute("""
                    INSERT INTO pago_residente (
                        id_residente, id_residencia, monto, fecha_pago, fecha_prevista,
                        mes_pagado, concepto, metodo_pago, estado, es_cobro_previsto
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id_pago
                """, (
                    id_residente,
                    id_residencia,
                    costo_habitacion,
                    None,
                    fecha_prevista.date(),
                    mes_pagado,
                    concepto,
                    metodo_pago,
                    'pendiente',
                    True
                ))
                
                cobros_generados += 1
                print(f"   ✅ {nombre} {apellido}: Cobro previsto generado (€{costo_habitacion})")
                
            except Exception as e:
                errores.append(f"Error al crear cobro para {nombre} {apellido}: {str(e)}")
                print(f"   ❌ {nombre} {apellido}: Error - {str(e)}")
        
        conn.commit()
        
        print("\n" + "=" * 60)
        print("📊 RESUMEN:")
        print(f"   ✅ Cobros generados: {cobros_generados}")
        print(f"   🗑️  Cobros eliminados: {cobros_eliminados}")
        print(f"   ⏭️  Cobros duplicados (ya completados): {cobros_duplicados}")
        print(f"   📅 Mes de referencia: {mes_siguiente}")
        print(f"   👥 Total residentes procesados: {len(residentes)}")
        
        if errores:
            print(f"\n   ⚠️  Errores: {len(errores)}")
            for error in errores:
                print(f"      • {error}")
        
        print("\n✅ Proceso completado exitosamente")
        
    except Exception as e:
        if conn:
            conn.rollback()
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
    regenerar_cobros_previstos()

