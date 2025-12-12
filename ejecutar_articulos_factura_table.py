#!/usr/bin/env python3
"""
Script para crear la tabla articulo_factura en la base de datos
"""

import psycopg2
from db_connector import get_db_connection

def crear_tabla_articulos():
    """Crea la tabla articulo_factura si no existe"""
    print("🔧 Conectando a la base de datos...")
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("📊 Creando tabla articulo_factura...")
        
        with open('add_articulos_factura_table.sql', 'r', encoding='utf-8') as f:
            sql = f.read()
        
        # Ejecutar el SQL
        cursor.execute(sql)
        conn.commit()
        
        print("✅ Tabla articulo_factura creada exitosamente")
        
        # Verificar que se creó
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'articulo_factura'
            ORDER BY ordinal_position;
        """)
        
        columnas = cursor.fetchall()
        print(f"\n📋 Columnas de la tabla (total: {len(columnas)}):")
        for col in columnas:
            print(f"   - {col[0]:25} ({col[1]})")
        
        # Ver índices
        cursor.execute("""
            SELECT indexname, indexdef 
            FROM pg_indexes 
            WHERE tablename = 'articulo_factura';
        """)
        indices = cursor.fetchall()
        print(f"\n🔍 Índices creados (total: {len(indices)}):")
        for idx in indices:
            print(f"   - {idx[0]}")
        
        print("\n✅ TABLA LISTA PARA USAR")
        print("\n💡 PRÓXIMOS PASOS:")
        print("   1. Reiniciar servidor Flask")
        print("   2. Procesar una factura con artículos")
        print("   3. Los artículos se guardarán automáticamente")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    crear_tabla_articulos()
