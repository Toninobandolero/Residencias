# 🏥 Sistema de Gestión de Residencias Violetas

Sistema de gestión interna para dos residencias de ancianos (Violetas 1 y Violetas 2).

## 🚀 Inicio Rápido

### 1. Instalación

```powershell
# Clonar repositorio
git clone https://github.com/Toninobandolero/Residencias.git
cd Residencias

# Instalar dependencias
pip install -r requirements.txt
```

### 2. Configuración Inicial

**Opción A: Con Cloud SQL Proxy (Recomendado - Solución Definitiva)**

```powershell
# 1. Configurar Cloud SQL Proxy (no necesitas autorizar IPs)
.\setup_cloud_sql_proxy.ps1

# 2. Configurar .env automáticamente
.\configurar_proxy_env.ps1

# 3. Iniciar servidor (inicia proxy y Flask juntos)
.\start_server_with_proxy.ps1
```

**Opción B: Conexión Directa (Requiere autorizar IP)**

```powershell
# 1. Crear archivo .env con tus credenciales
# 2. Autorizar tu IP en Cloud SQL Console
# 3. Iniciar servidor
.\start_server.ps1
```

### 3. Acceder al Sistema

- **URL**: http://localhost:5000
- **Usuario**: `admin@violetas1.com`
- **Contraseña**: `admin123`

---

## 📋 Características Principales

### Gestión de Residentes
- Listado, creación y edición de residentes
- Información completa: habitación, costos, servicios, medicaciones
- Documentos adjuntos
- Filtrado automático por residencia

### Facturación
- Cobros previstos (generación automática)
- Cobros completados
- Pagos a proveedores
- Gráficos de estimaciones mensuales
- Estadísticas de facturación

### Personal
- Gestión del personal de la residencia
- Información de contacto y cargos

### Seguridad
- Autenticación JWT
- Separación de datos por residencia
- Filtrado automático por `id_residencia`

---

## 🛠️ Stack Tecnológico

- **Backend**: Python 3.11+ (Flask, PyJWT, Werkzeug)
- **Base de Datos**: PostgreSQL (Cloud SQL en GCP)
- **Frontend**: HTML/CSS/JavaScript (SPA)
- **Autenticación**: JWT con expiración de 24 horas

---

## 📁 Estructura del Proyecto

```
.
├── app.py                      # Aplicación principal Flask
├── db_connector.py             # Conexión a PostgreSQL
├── static/
│   └── index.html             # Frontend SPA
├── .env                       # Variables de entorno (no versionado)
├── requirements.txt            # Dependencias Python
├── create_schema.sql           # Esquema de base de datos
└── README.md                  # Este archivo
```

---

## ⚙️ Configuración de Variables de Entorno

Crear archivo `.env` en la raíz del proyecto:

```env
# Base de Datos
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=tu-contraseña
DB_PORT=5432

# Opción A: Con Cloud SQL Proxy (Recomendado)
DB_USE_PROXY=true
DB_HOST=127.0.0.1
CLOUD_SQL_CONNECTION_NAME=residencias-479706:europe-west9:residencias
GOOGLE_APPLICATION_CREDENTIALS=residencias-479706-8c3bdbf8bbf8.json

# Opción B: Conexión Directa
# DB_USE_PROXY=false
# DB_HOST=34.155.185.9

# Autenticación
JWT_SECRET_KEY=tu-clave-secreta-muy-segura
```

---

## 🚀 Scripts Disponibles

### Inicio del Servidor

```powershell
# Con Cloud SQL Proxy (Recomendado)
.\start_server_with_proxy.ps1

# Sin Proxy (requiere IP autorizada)
.\start_server.ps1
```

### Configuración

```powershell
# Configurar Cloud SQL Proxy
.\setup_cloud_sql_proxy.ps1

# Configurar .env para proxy
.\configurar_proxy_env.ps1
```

### Utilidades

```powershell
# Backup de base de datos
.\backup.ps1

# Obtener IP pública actual
python obtener_mi_ip.py

# Diagnosticar sistema
python diagnostico_sistema.py

# Probar conexión a BD
python test_conexion_bd.py
```

---

## 🔐 Autenticación

### Login

```bash
POST /api/v1/login
Content-Type: application/json

{
  "email": "admin@violetas1.com",
  "password": "admin123"
}
```

### Uso del Token

Todas las peticiones protegidas requieren:

```
Authorization: Bearer <token_jwt>
```

El token contiene:
- `id_usuario`: ID del usuario
- `id_rol`: ID del rol
- `id_residencia`: ID de la residencia (filtrado automático)
- `exp`: Fecha de expiración (24 horas)

---

## 📡 Endpoints Principales

### Públicos
- `GET /health` - Health check
- `POST /api/v1/login` - Autenticación

### Protegidos (requieren token JWT)

**Residentes:**
- `GET /api/v1/residentes` - Listar residentes
- `GET /api/v1/residentes/<id>` - Obtener residente
- `POST /api/v1/residentes` - Crear residente
- `PUT /api/v1/residentes/<id>` - Actualizar residente

**Facturación:**
- `GET /api/v1/facturacion/cobros` - Listar cobros
- `POST /api/v1/facturacion/cobros` - Crear cobro
- `PUT /api/v1/facturacion/cobros/<id>` - Actualizar cobro
- `GET /api/v1/facturacion/cobros/estadisticas` - Estadísticas

**Proveedores:**
- `GET /api/v1/proveedores` - Listar proveedores
- `POST /api/v1/proveedores` - Crear proveedor
- `GET /api/v1/facturacion/proveedores` - Listar pagos a proveedores

**Personal:**
- `GET /api/v1/personal` - Listar personal

> Para lista completa de endpoints, ver `REFERENCIA_API.md`

---

## 🗄️ Base de Datos

### Tablas Principales

- `residencia` - Residencias (Violetas 1 y Violetas 2)
- `usuario` - Usuarios del sistema
- `residente` - Residentes
- `pago_residente` - Pagos de residentes
- `proveedor` - Proveedores
- `pago_proveedor` - Pagos a proveedores
- `personal` - Personal de la residencia

### Crear Esquema

```powershell
python create_database.py
```

---

## 🔒 Seguridad

**IMPERATIVO**: Todo acceso a datos filtra automáticamente por `id_residencia` obtenida del token de sesión. El personal de Violetas 1 no puede ver datos de Violetas 2.

- Filtrado obligatorio por `id_residencia` en todas las consultas
- Tokens JWT con expiración de 24 horas
- Contraseñas hasheadas con Werkzeug
- Validación de entrada en todos los endpoints

---

## 📚 Documentación Adicional

- **`GUIA_TECNICA.md`** - Configuración avanzada, Cloud SQL Proxy, solución de problemas
- **`REFERENCIA_API.md`** - Referencia completa de endpoints, estructura de datos, scripts

---

## 🆘 Solución de Problemas Rápida

### No se conecta a la base de datos

**Solución 1: Usar Cloud SQL Proxy (Recomendado)**
```powershell
.\setup_cloud_sql_proxy.ps1
.\configurar_proxy_env.ps1
.\start_server_with_proxy.ps1
```

**Solución 2: Autorizar IP en Cloud SQL**
1. Obtener IP: `python obtener_mi_ip.py`
2. Autorizar en: https://console.cloud.google.com/sql/instances/residencias/overview
3. Agregar red: `TU_IP/32`

### No se listan los residentes

1. Verificar conexión: `python test_conexion_bd.py`
2. Verificar token en localStorage (F12 → Console)
3. Verificar que hay residentes en la BD para tu `id_residencia`

> Para más detalles, ver `GUIA_TECNICA.md`

---

## 👤 Usuario de Prueba

- **Email**: `admin@violetas1.com`
- **Contraseña**: `admin123`
- **Rol**: Administrador
- **Residencia**: Violetas 1 (ID: 1)

---

## 📝 Convenciones

- **Nomenclatura**: snake_case para tablas, campos y funciones Python
- **Seguridad**: Filtrado obligatorio por `id_residencia` en todas las consultas
- **Tokens**: Expiración de 24 horas

---

## 📄 Licencia

Este proyecto es privado y está destinado para uso interno de las residencias Violetas.

## 👥 Autor

**toninobandolero**

---

Para más información técnica, consulta:
- `GUIA_TECNICA.md` - Configuración avanzada y solución de problemas
- `REFERENCIA_API.md` - Referencia completa de la API
