# Guía para Obtener los Datos de Conexión a PostgreSQL

## 1. Credenciales de Conexión (Cloud SQL en GCP)

### Opción A: Desde la Consola de GCP
1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Navega a **SQL** (Cloud SQL)
3. Selecciona tu instancia de PostgreSQL
4. En la pestaña **"Información general"** encontrarás:
   - **IP pública** o **IP privada** → `DB_HOST`
   - **Nombre de la base de datos** → `DB_NAME`
   - **Usuario** → `DB_USER`
   - **Puerto** → `DB_PORT` (generalmente 5432)

### Opción B: Desde la línea de comandos (gcloud)
```bash
# Listar instancias de Cloud SQL
gcloud sql instances list

# Obtener detalles de una instancia específica
gcloud sql instances describe NOMBRE_INSTANCIA

# Obtener la IP de conexión
gcloud sql instances describe NOMBRE_INSTANCIA --format="value(ipAddresses[0].ipAddress)"
```

### Para la contraseña:
- Si la olvidaste, puedes restablecerla desde la consola de GCP
- O usa la contraseña que configuraste al crear la instancia

## 2. Verificar Estructura de la Tabla `usuario`

Una vez que tengas las credenciales en el `.env`, ejecuta:

```bash
python db_utils.py verify
```

Esto te mostrará si la tabla tiene la estructura correcta.

## 3. Obtener IDs de Roles y Residencias

Puedes consultar directamente en PostgreSQL:

```sql
-- Ver todas las residencias
SELECT id_residencia, nombre FROM residencia;

-- Ver todos los roles
SELECT id_rol, nombre FROM rol;

-- Ver usuarios existentes (sin mostrar contraseñas)
SELECT id_usuario, email, id_rol, id_residencia FROM usuario;
```

## 4. Script de Consulta Rápida

También puedes usar este script Python para consultar:

```python
from db_connector import get_db_connection

conn = get_db_connection()
cursor = conn.cursor()

# Ver residencias
cursor.execute("SELECT id_residencia, nombre FROM residencia")
print("Residencias:")
for row in cursor.fetchall():
    print(f"  ID: {row[0]}, Nombre: {row[1]}")

# Ver roles
cursor.execute("SELECT id_rol, nombre FROM rol")
print("\nRoles:")
for row in cursor.fetchall():
    print(f"  ID: {row[0]}, Nombre: {row[1]}")

cursor.close()
conn.close()
```

