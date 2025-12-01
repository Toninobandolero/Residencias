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

**Opción A: Con Cloud SQL Proxy (Recomendado)**

```powershell
# 1. Configurar Cloud SQL Proxy
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

### 3. Crear Super Administrador

El sistema requiere un super administrador inicial:

```powershell
python init_database.py
```

**Credenciales por defecto:**
- Email: `admin@residencias.com`
- Password: `CambiarContraseña123!`
- ⚠️ **IMPORTANTE**: Deberás cambiar la contraseña en el primer login

### 4. Acceder al Sistema

- **URL**: http://localhost:5000
- **Usuario**: `admin@residencias.com`
- **Contraseña**: `CambiarContraseña123!` (luego cambiarás esta)

---

## 📋 Características Principales

### Gestión de Residentes
- Listado, creación y edición de residentes
- Información completa: habitación, costos, servicios, medicaciones
- Documentos adjuntos (Cloud Storage)
- Filtrado automático por residencia

### Facturación
- Cobros previstos (generación automática mensual)
- Cobros completados
- Pagos a proveedores
- Gráficos de estimaciones mensuales
- Estadísticas de facturación

### Personal
- Gestión del personal de la residencia
- Información de contacto y cargos
- Turnos y asistencia

### Seguridad Avanzada
- Autenticación JWT con expiración de 24 horas
- Sistema de roles y permisos granulares (ACL)
- Multi-residencia (usuarios pueden acceder a múltiples residencias)
- Super administrador con acceso total
- Cambio obligatorio de contraseña en primer login
- Rate limiting para prevenir ataques de fuerza bruta

---

## 🛠️ Stack Tecnológico

- **Backend**: Python 3.11+ (Flask, PyJWT, Werkzeug)
- **Base de Datos**: PostgreSQL (Cloud SQL en GCP)
- **Frontend**: HTML/CSS/JavaScript (SPA)
- **Almacenamiento**: Google Cloud Storage (documentos)
- **Autenticación**: JWT con expiración de 24 horas

---

## 📁 Estructura del Proyecto

```
.
├── app.py                      # Aplicación principal Flask
├── db_connector.py             # Conexión a PostgreSQL
├── init_database.py            # Script para crear super_admin
├── static/
│   └── index.html             # Frontend SPA
├── .env                       # Variables de entorno (no versionado)
├── requirements.txt            # Dependencias Python
├── create_schema.sql           # Esquema de base de datos
└── README.md                  # Este archivo
```

---

## 📚 Documentación

La documentación está organizada en 5 documentos principales:

1. **`README.md`** (este archivo) - Inicio rápido y características
2. **`GUIA_INSTALACION_Y_CONFIGURACION.md`** - Instalación detallada, configuración de Cloud SQL, base de datos
3. **`GUIA_SEGURIDAD_Y_USUARIOS.md`** - Sistema de seguridad, autenticación, gestión de usuarios y roles
4. **`REFERENCIA_API.md`** - Referencia completa de endpoints de la API
5. **`GUIA_TECNICA.md`** - Troubleshooting, desarrollo, detalles técnicos

---

## 🔐 Sistema de Usuarios

### Super Administrador

- **Acceso total** a todas las residencias
- Puede crear otros usuarios (incluyendo otros super_admin)
- Bypass completo de permisos
- **Solo debe haber UN super_admin** (o muy pocos)

### Usuarios Administradores

- Acceso a residencias asignadas (pueden ser múltiples)
- Permisos según su rol
- Gestión de datos de las residencias asignadas

### Crear Usuarios

Solo el super_admin puede crear usuarios mediante el endpoint:
- `POST /api/v1/usuarios`

Ver `GUIA_SEGURIDAD_Y_USUARIOS.md` para más detalles.

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
3. Verificar que hay residentes en la BD para tus residencias asignadas

> Para más detalles, ver `GUIA_TECNICA.md`

---

## 🔒 Seguridad

El sistema implementa múltiples capas de seguridad:

- ✅ **Autenticación JWT** con expiración de 24 horas
- ✅ **Separación de datos por residencia** (filtrado automático)
- ✅ **Sistema de roles y permisos granulares** (ACL)
- ✅ **Contraseñas hasheadas** con Werkzeug
- ✅ **Cambio obligatorio de contraseña** en primer login
- ✅ **Rate limiting** para prevenir ataques de fuerza bruta
- ✅ **Validación de entrada** en todos los endpoints

---

## 📝 Convenciones

- **Nomenclatura**: snake_case para tablas, campos y funciones Python
- **Seguridad**: Filtrado automático por residencias asignadas
- **Tokens**: Expiración de 24 horas
- **Roles**: Sistema jerárquico con super_admin como máximo nivel

---

## 📄 Licencia

Este proyecto es privado y está destinado para uso interno de las residencias Violetas.

## 👥 Autor

**toninobandolero**

---

## 📖 Más Información

- **`GUIA_INSTALACION_Y_CONFIGURACION.md`** - Configuración detallada paso a paso
- **`GUIA_SEGURIDAD_Y_USUARIOS.md`** - Sistema de seguridad y gestión de usuarios
- **`REFERENCIA_API.md`** - Referencia completa de la API
- **`GUIA_TECNICA.md`** - Troubleshooting y detalles técnicos
