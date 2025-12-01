# ✅ Super Admin Creado Exitosamente

## 🎉 Estado Actual

El sistema ahora tiene configurado el **Super Administrador** con las siguientes credenciales:

### Credenciales del Super Admin

- **Email**: `admin@residencias.com`
- **Password**: `CambiarContraseña123!`
- **ID Usuario**: 3
- **Rol**: Super Administrador (id_rol = 1)
- **Acceso**: Total (todas las residencias)
- **Residencias asignadas**: Ninguna (acceso ilimitado)

## 🔐 Primer Login

**IMPORTANTE**: En el primer login, el sistema te pedirá cambiar la contraseña.

### Pasos para el primer acceso:

1. Ir a: `http://localhost:5000`
2. Usar las credenciales:
   - Email: `admin@residencias.com`
   - Password: `CambiarContraseña123!`
3. El sistema te redirigirá para cambiar la contraseña
4. Establecer una nueva contraseña segura

## 👥 Próximos Pasos: Crear Usuarios Administradores

Como mencionaste, el super_admin debe crear:
- **2 usuarios administradores** que verán todo en la app

### Crear Usuarios Administradores

Después de hacer login como super_admin, puedes crear usuarios mediante:

**Endpoint**: `POST /api/v1/usuarios`

```json
{
  "email": "admin1@violetas.com",
  "password": "ContraseñaSegura123!",
  "id_rol": 2,
  "id_residencias": [1, 2],
  "nombre": "Administrador",
  "apellido": "Violetas 1"
}
```

### Notas Importantes:

1. ⚠️ **El super_admin puede crear otros super_admin** si lo necesita
2. ⚠️ **Solo el super_admin puede crear usuarios** (endpoint protegido)
3. ✅ **Los usuarios nuevos requieren cambio de contraseña** en primer login
4. ✅ **Puedes asignar múltiples residencias** a cada usuario usando `id_residencias`

## 📋 Estructura de Roles Recomendada

- **id_rol = 1**: `super_admin` - Acceso total, puede crear usuarios
- **id_rol = 2**: `Administrador` - Puede ver todo en la app (asignar según necesidad)
- **id_rol = 3**: `Director` - Gestión de residencia
- **id_rol = 4+**: Otros roles según necesites

## 🔧 Configuración Personalizada

Si quieres cambiar las credenciales del super_admin, edita el archivo `.env`:

```env
SUPER_ADMIN_EMAIL=tu_email@ejemplo.com
SUPER_ADMIN_PASSWORD=TuContraseñaSegura123!
```

Luego ejecuta: `python init_database.py` (solo creará si no existe)

## ✅ Verificación

Para verificar el estado actual del sistema:

```powershell
python -c "from db_connector import get_db_connection; conn = get_db_connection(); cursor = conn.cursor(); cursor.execute('SELECT id_usuario, email, id_rol FROM usuario'); print('\n'.join([f'ID: {u[0]}, Email: {u[1]}, Rol: {u[2]}' for u in cursor.fetchall()])); cursor.close(); conn.close()"
```

---

**Estado**: ✅ Super Admin creado y listo para usar

