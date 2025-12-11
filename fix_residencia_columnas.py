#!/usr/bin/env python3
"""
Script para agregar columnas faltantes a la tabla residencia.
"""
import os
from dotenv import load_dotenv

if os.path.exists('.env'):
    load_dotenv()

from db_connector import get_db_connection

def fix_residencia_columnas():
    """Agrega columnas faltantes a la tabla residencia."""
    print("=" * 70)
    print("  FIX: Columnas de tabla residencia")
    print("=" * 70)
    print()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Verificar columnas actuales
        print("📝 Paso 1: Verificando columnas actuales...")
        cursor.execute("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'residencia'
            ORDER BY ordinal_position
        """)
        
        columnas_actuales = cursor.fetchall()
        print(f"  ✅ {len(columnas_actuales)} columnas encontradas:")
        for col in columnas_actuales:
            print(f"     • {col[0]:25s} ({col[1]})")
        
        # 2. Agregar columnas faltantes
        print()
        print("📝 Paso 2: Agregando columnas faltantes...")
        
        cursor.execute("""
            ALTER TABLE residencia 
            ADD COLUMN IF NOT EXISTS nombre_fiscal VARCHAR(255),
            ADD COLUMN IF NOT EXISTS nif VARCHAR(20),
            ADD COLUMN IF NOT EXISTS codigo_postal VARCHAR(10),
            ADD COLUMN IF NOT EXISTS ciudad VARCHAR(100),
            ADD COLUMN IF NOT EXISTS provincia VARCHAR(100),
            ADD COLUMN IF NOT EXISTS email VARCHAR(255),
            ADD COLUMN IF NOT EXISTS web VARCHAR(255),
            ADD COLUMN IF NOT EXISTS cuenta_bancaria VARCHAR(34),
            ADD COLUMN IF NOT EXISTS observaciones TEXT
        """)
        conn.commit()
        print("  ✅ Columnas agregadas correctamente")
        
        # 3. Verificar columnas después de agregar
        print()
        print("📝 Paso 3: Verificando columnas después de agregar...")
        cursor.execute("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'residencia'
            ORDER BY ordinal_position
        """)
        
        columnas_nuevas = cursor.fetchall()
        print(f"  ✅ {len(columnas_nuevas)} columnas totales:")
        for col in columnas_nuevas:
            print(f"     • {col[0]:25s} ({col[1]})")
        
        cursor.close()
        conn.close()
        
        print()
        print("=" * 70)
        print("  ✅ PROCESO COMPLETADO EXITOSAMENTE")
        print("=" * 70)
        print()
        print("💡 SIGUIENTE PASO:")
        print("   Intenta editar una residencia ahora.")
        print()
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == '__main__':
    fix_residencia_columnas()
