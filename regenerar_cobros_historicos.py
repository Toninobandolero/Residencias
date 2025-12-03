"""
Script para regenerar cobros históricos completados para todos los residentes.
Útil para corregir residentes que fueron creados recientemente pero tienen fecha_ingreso anterior.
"""
from db_connector import get_db_connection
from datetime import datetime
from app import generar_cobros_historicos_completados

def regenerar_cobros_historicos():
    """
    Regenera cobros históricos completados para todos los residentes activos
    que tienen fecha_ingreso y costo_habitacion pero pueden tener cobros faltantes.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        print("\n" + "="*70)
        print("REGENERACIÓN DE COBROS HISTÓRICOS COMPLETADOS")
        print("="*70 + "\n")
        
        # Obtener todos los residentes activos con fecha_ingreso y costo_habitacion
        cursor.execute("""
            SELECT id_residente, nombre, apellido, fecha_ingreso, costo_habitacion, 
                   metodo_pago_preferido, id_residencia
            FROM residente
            WHERE activo = TRUE
              AND fecha_ingreso IS NOT NULL
              AND costo_habitacion IS NOT NULL
              AND costo_habitacion > 0
            ORDER BY id_residente
        """)
        
        residentes = cursor.fetchall()
        print(f"📋 Residentes encontrados: {len(residentes)}\n")
        
        total_cobros_generados = 0
        residentes_procesados = 0
        
        for residente in residentes:
            id_residente, nombre, apellido, fecha_ingreso, costo_habitacion, metodo_pago, id_residencia = residente
            
            # Verificar cuántos cobros históricos completados tiene actualmente
            cursor.execute("""
                SELECT COUNT(*) FROM pago_residente
                WHERE id_residente = %s
                  AND estado = 'cobrado'
                  AND es_cobro_previsto = FALSE
            """, (id_residente,))
            cobros_existentes = cursor.fetchone()[0]
            
            # Calcular cuántos cobros debería tener
            if isinstance(fecha_ingreso, str):
                fecha_ingreso_date = datetime.strptime(fecha_ingreso, '%Y-%m-%d').date()
            else:
                fecha_ingreso_date = fecha_ingreso
            
            hoy = datetime.now().date()
            mes_actual = datetime(hoy.year, hoy.month, 1).date()
            mes_ingreso = datetime(fecha_ingreso_date.year, fecha_ingreso_date.month, 1).date()
            
            meses_esperados = 0
            if mes_ingreso <= mes_actual:
                fecha_temp = mes_ingreso
                while fecha_temp <= mes_actual:
                    meses_esperados += 1
                    if fecha_temp.month == 12:
                        fecha_temp = datetime(fecha_temp.year + 1, 1, 1).date()
                    else:
                        fecha_temp = datetime(fecha_temp.year, fecha_temp.month + 1, 1).date()
            
            # Si faltan cobros, regenerar
            if cobros_existentes < meses_esperados:
                print(f"🔄 {nombre} {apellido} (ID: {id_residente}):")
                print(f"   Cobros existentes: {cobros_existentes}, Esperados: {meses_esperados}")
                print(f"   Fecha ingreso: {fecha_ingreso_date}, Costo: {costo_habitacion}€")
                
                # Eliminar cobros históricos existentes para regenerarlos (opcional, comentado por seguridad)
                # cursor.execute("""
                #     DELETE FROM pago_residente
                #     WHERE id_residente = %s
                #       AND estado = 'cobrado'
                #       AND es_cobro_previsto = FALSE
                # """, (id_residente,))
                
                # Regenerar cobros históricos
                try:
                    cobros_generados = generar_cobros_historicos_completados(
                        cursor, id_residente, id_residencia, fecha_ingreso_date, 
                        costo_habitacion, metodo_pago or 'transferencia'
                    )
                    conn.commit()
                    
                    if cobros_generados > 0:
                        print(f"   ✅ Generados {cobros_generados} cobros históricos nuevos")
                        total_cobros_generados += cobros_generados
                    else:
                        print(f"   ⚠️  No se generaron cobros nuevos (posiblemente ya existen)")
                    
                    residentes_procesados += 1
                except Exception as e:
                    conn.rollback()
                    print(f"   ❌ Error al generar cobros: {str(e)}")
                
                print()
        
        print("="*70)
        print(f"✅ Proceso completado:")
        print(f"   Residentes procesados: {residentes_procesados}")
        print(f"   Total de cobros generados: {total_cobros_generados}")
        print("="*70 + "\n")
        
    except Exception as e:
        conn.rollback()
        print(f"❌ ERROR: {str(e)}")
        import traceback
        print(traceback.format_exc())
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    import sys
    # Permitir ejecución automática con --yes o -y
    if len(sys.argv) > 1 and sys.argv[1] in ['--yes', '-y', '--force']:
        regenerar_cobros_historicos()
    else:
        respuesta = input("¿Deseas regenerar los cobros históricos para todos los residentes? (s/n): ")
        if respuesta.lower() == 's':
            regenerar_cobros_historicos()
        else:
            print("Operación cancelada.")

