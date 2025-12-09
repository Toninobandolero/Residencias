"""
Script para ejecutar el script SQL de mapeo de campos de IA.
"""
from dotenv import load_dotenv
from db_connector import get_db_connection

load_dotenv()


def ejecutar_script_mapeo():
    """Lee y ejecuta el script SQL para crear la tabla de mapeo de campos de IA."""
    print("\n" + "="*60)
    print("EJECUTANDO SCRIPT DE MAPEO DE CAMPOS DE IA")
    print("="*60)
    
    # Leer el archivo SQL
    try:
        with open('add_mapeo_campos_ia_table.sql', 'r', encoding='utf-8') as f:
            sql_script = f.read()
    except FileNotFoundError:
        print("❌ Error: No se encontró el archivo add_mapeo_campos_ia_table.sql")
        return False
    
    # Conectar a la base de datos
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("\nEjecutando script SQL...")
        
        # Ejecutar el script completo de una vez (mejor para CREATE TABLE IF NOT EXISTS)
        try:
            cursor.execute(sql_script)
            print("  ✓ Script SQL ejecutado correctamente")
        except Exception as e:
            # Si hay error, intentar ejecutar sentencia por sentencia
            print(f"  ⚠ Error al ejecutar script completo, intentando sentencia por sentencia...")
            print(f"  Error: {str(e)[:100]}")
            
            # Dividir el script en sentencias individuales
            sentencias = []
            current_sentencia = ""
            for line in sql_script.split('\n'):
                line = line.strip()
                if not line or line.startswith('--'):
                    continue
                current_sentencia += line + " "
                if line.endswith(';'):
                    sentencias.append(current_sentencia.strip())
                    current_sentencia = ""
            
            if current_sentencia.strip():
                sentencias.append(current_sentencia.strip())
            
            for i, sentencia in enumerate(sentencias, 1):
                if sentencia and not sentencia.startswith('--'):
                    try:
                        cursor.execute(sentencia)
                        print(f"  ✓ Sentencia {i} ejecutada correctamente")
                    except Exception as e:
                        # Algunos errores son esperados (como "ya existe", "duplicate key")
                        error_str = str(e).lower()
                        if any(x in error_str for x in ['already exists', 'duplicate', 'does not exist']):
                            print(f"  ⚠ Sentencia {i}: {str(e)[:80]}... (continuando)")
                        else:
                            print(f"  ❌ Error en sentencia {i}: {str(e)}")
                            raise
        
        conn.commit()
        
        print("\n✅ Script ejecutado exitosamente!")
        
        # Verificar que la tabla se creó correctamente
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public'
                AND table_name = 'mapeo_campos_ia'
            )
        """)
        tabla_existe = cursor.fetchone()[0]
        
        if tabla_existe:
            print("✅ Tabla 'mapeo_campos_ia' creada correctamente")
            
            # Contar registros insertados
            cursor.execute("SELECT COUNT(*) FROM mapeo_campos_ia")
            count = cursor.fetchone()[0]
            print(f"✅ Registros en la tabla: {count}")
            
            # Mostrar algunos registros de ejemplo
            cursor.execute("SELECT campo_sistema, campo_ia, activo FROM mapeo_campos_ia ORDER BY campo_sistema LIMIT 5")
            registros = cursor.fetchall()
            print("\nPrimeros registros:")
            for reg in registros:
                estado = "✓ Activo" if reg[2] else "✗ Inactivo"
                print(f"  - {reg[0]} → {reg[1]} ({estado})")
        else:
            print("❌ Error: La tabla no se creó correctamente")
            return False
        
        cursor.close()
        conn.close()
        
        print("\n" + "="*60)
        print("✅ Mapeo de campos de IA configurado correctamente!")
        print("\nAhora puedes usar la interfaz de configuración en el frontend")
        print("para personalizar el mapeo según tus necesidades.")
        print("="*60 + "\n")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error al ejecutar el script: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    ejecutar_script_mapeo()

