# 🔐 Instrucciones para Crear el Super Admin

## ¿Qué es el Super Admin?

El **Super Admin** es un usuario especial con acceso total al sistema:
- ✅ Acceso a **TODAS** las residencias
- ✅ Puede crear otros usuarios
- ✅ Bypass completo de permisos
- ✅ **NO** requiere residencias asignadas (acceso ilimitado)

## Crear el Super Admin

### Paso 1: Ejecutar el Script de Inicialización

```powershell
python init_database.py
```

Este script:
- Crea el usuario super_admin con `id_rol = 1`
- Usa variables de entorno para email/contraseña
- Verifica que no exista duplicado
- Requiere cambio de contraseña en primer login

### Paso 2: Configurar Credenciales (Opcional)

Si quieres personalizar las credenciales, agrega al archivo `.env`:

```env
# Credenciales del Super Admin
SUPER_ADMIN_EMAIL=admin@residencias.com
SUPER_ADMIN_PASSWORD=CambiarContraseña123!
```

**Valores por defecto** (si no se especifican):
- Email: `admin@residencias.com`
- Password: `CambiarContraseña123!`

### Paso 3: Verificar que el Rol Existe

Antes de ejecutar el script, asegúrate de que existe el rol con `id_rol = 1`:

```sql
SELECT id_rol, nombre FROM rol WHERE id_rol = 1;
```

Si no existe, créalo:

```sql
INSERT INTO rol (id_rol, nombre) VALUES (1, 'super_admin');
```

## Login del Super Admin

### Primer Login

1. **Email**: `admin@residencias.com` (o el que configuraste)
2. **Password**: `CambiarContraseña123!` (o el que configuraste)
3. **Importante**: El sistema te pedirá cambiar la contraseña inmediatamente

### Después del Cambio de Contraseña

- Usa tu nueva contraseña para futuros logins
- Ya no se te pedirá cambiar la contraseña

## Diferencias Clave

| Característica | Usuario Normal | Super Admin |
|----------------|----------------|-------------|
| **Email** | `admin@violetas1.com` | `admin@residencias.com` |
| **Password** | `admin123` | `CambiarContraseña123!` |
| **Acceso** | Solo su residencia | Todas las residencias |
| **Permisos** | Limitados por rol | Totales (bypass) |
| **Residencias** | Asignadas en `usuario_residencia` | Ninguna (acceso total) |

## Verificar que el Super Admin Existe

```sql
SELECT id_usuario, email, id_rol, requiere_cambio_clave 
FROM usuario 
WHERE id_rol = 1;
```

## Notas Importantes

1. ⚠️ **Solo debe haber UN super_admin** (o muy pocos)
2. ⚠️ **NUNCA** crees super_admin a través de la API
3. ⚠️ **Siempre** usa el script `init_database.py`
4. ✅ El super_admin puede crear otros usuarios (incluyendo otros super_admin)
5. ✅ El super_admin puede asignarse residencias si quiere limitar acceso

## Ejemplo de Uso

```powershell
# 1. Verificar que el rol existe
python -c "from db_connector import get_db_connection; conn = get_db_connection(); cursor = conn.cursor(); cursor.execute('SELECT id_rol, nombre FROM rol WHERE id_rol = 1'); print(cursor.fetchone()); cursor.close(); conn.close()"

# 2. Crear super_admin
python init_database.py

# 3. Verificar creación
python -c "from db_connector import get_db_connection; conn = get_db_connection(); cursor = conn.cursor(); cursor.execute('SELECT id_usuario, email, id_rol FROM usuario WHERE id_rol = 1'); print(cursor.fetchone()); cursor.close(); conn.close()"
```

