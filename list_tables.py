"""Script simple para listar las tablas existentes."""
from dotenv import load_dotenv
load_dotenv()
from db_connector import get_db_connection

conn = get_db_connection()
cursor = conn.cursor()

cursor.execute("""
    SELECT table_name 
    FROM information_schema.tables 
    WHERE table_schema = 'public' 
    ORDER BY table_name
""")

tables = cursor.fetchall()

print("\nTablas existentes en la base de datos:")
print("=" * 50)
if tables:
    for table in tables:
        print(f"  - {table[0]}")
else:
    print("  (ninguna tabla encontrada)")

cursor.close()
conn.close()

