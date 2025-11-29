# Sistema de Gestión de Residencias Violetas

MVP (Producto Mínimo Viable) de software de gestión interna para dos residencias de ancianos (Violetas 1 y Violetas 2).

## 🚀 Stack Tecnológico

- **Backend**: Python 3.11+ (Flask, PyJWT, Werkzeug)
- **Base de Datos**: PostgreSQL (Cloud SQL en GCP)
- **Alojamiento**: GCP Cloud Run
- **Frontend**: HTML/CSS/JavaScript (SPA)

## 🔒 Seguridad y Separación de Datos

**IMPERATIVO**: Todo acceso a datos filtra automáticamente por `id_residencia` obtenida del token de sesión. El personal de Violetas 1 no puede ver datos de Violetas 2.

## 📋 Características Implementadas

### Autenticación
- Login con Email/Contraseña
- Tokens JWT con expiración de 24 horas
- Middleware de autenticación automática
- Hashing seguro de contraseñas con Werkzeug

### Gestión de Residentes
- Listado de residentes (filtrado por residencia)
- Crear nuevo residente
- Ver/Editar información completa del residente
- Campos adicionales:
  - Habitación asignada
  - Costo de habitación
  - Servicios extra
  - Medicaciones
  - Peculiaridades/Notas importantes

### Gestión de Pagos
- Listado de pagos de residentes
- Registro de nuevos pagos

### Gestión de Personal
- Listado del personal de la residencia

## 🗄️ Estructura de Base de Datos

El sistema incluye las siguientes tablas:
- `residencia` - Residencias (Violetas 1 y Violetas 2)
- `rol` - Roles de usuario
- `usuario` - Usuarios del sistema
- `residente` - Residentes
- `personal` - Personal de la residencia
- `pago_residente` - Pagos de residentes
- `pago_proveedor` - Pagos a proveedores
- `turno_normal` - Turnos normales del personal
- `turno_extra` - Turnos extra del personal
- `registro_asistencial` - Registros asistenciales

## 🛠️ Instalación

### Requisitos
- Python 3.11+
- PostgreSQL (Cloud SQL en GCP o local)
- Git

### Pasos

1. **Clonar el repositorio**
   ```bash
   git clone https://github.com/Toninobandolero/Residencias.git
   cd Residencias
   ```

2. **Instalar dependencias**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configurar variables de entorno**
   
   Crear archivo `.env` con:
   ```env
   DB_HOST=tu-host-postgresql
   DB_NAME=postgres
   DB_USER=postgres
   DB_PASSWORD=tu-contraseña
   DB_PORT=5432
   JWT_SECRET_KEY=tu-clave-secreta-muy-segura
   ```

4. **Crear esquema de base de datos**
   ```bash
   python create_database.py
   ```

5. **Iniciar el servidor**
   ```bash
   python app.py
   ```
   
   O usar el script:
   ```bash
   .\restart_server.ps1
   ```

6. **Acceder a la aplicación**
   
   Abre tu navegador en: `http://localhost:5000`

## 👤 Usuario de Prueba

- **Email**: `admin@violetas1.com`
- **Contraseña**: `admin123`
- **Rol**: Administrador
- **Residencia**: Violetas 1

## 📡 Endpoints API

### Públicos
- `GET /health` - Health check
- `POST /api/v1/login` - Autenticación

### Protegidos (requieren token JWT)
- `GET /api/v1/residentes` - Listar residentes
- `GET /api/v1/residentes/<id>` - Obtener residente
- `POST /api/v1/residentes` - Crear residente
- `PUT /api/v1/residentes/<id>` - Actualizar residente
- `GET /api/v1/pagos-residentes` - Listar pagos
- `POST /api/v1/pagos-residentes` - Crear pago
- `GET /api/v1/personal` - Listar personal

## 🔐 Uso del Token JWT

Todas las peticiones a endpoints protegidos requieren el header:
```
Authorization: Bearer <tu_token_jwt>
```

El token contiene:
- `id_usuario`: ID del usuario
- `id_rol`: ID del rol
- `id_residencia`: ID de la residencia (usado para filtrar datos)
- `exp`: Fecha de expiración

## 📝 Convenciones

- **Nomenclatura**: snake_case para tablas, campos y funciones Python
- **Seguridad**: Filtrado obligatorio por `id_residencia` en todas las consultas
- **Tokens**: Expiración de 24 horas

## 📂 Estructura del Proyecto

```
.
├── app.py                      # Aplicación principal Flask
├── db_connector.py             # Conexión a PostgreSQL
├── requirements.txt            # Dependencias Python
├── create_schema.sql           # Esquema de base de datos
├── create_database.py          # Script para crear BD
├── static/
│   └── index.html             # Frontend SPA
├── .env                       # Variables de entorno (no versionado)
└── README.md                  # Este archivo
```

## 🚀 Scripts Útiles

- `restart_server.ps1` - Reinicia el servidor Flask
- `start_server.ps1` - Inicia el servidor
- `stop_server.ps1` - Detiene el servidor
- `check_db_info.py` - Consulta información de la BD
- `db_utils.py` - Utilidades para gestionar usuarios

## 📄 Licencia

Este proyecto es privado y está destinado para uso interno de las residencias Violetas.

## 👥 Autor

**toninobandolero**

---

Para más información sobre el desarrollo, consulta los archivos de documentación en el repositorio.

