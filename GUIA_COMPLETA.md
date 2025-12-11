# 📚 Gu

ía Completa - Instalación, Configuración y Uso

**Sistema de Gestión de Residencias Violetas**

Esta guía completa cubre todo lo necesario para instalar, configurar y comenzar a usar el sistema.

---

## 📋 Tabla de Contenidos

1. [Requisitos Previos](#1-requisitos-previos)
2. [Instalación Local](#2-instalación-local)
3. [Configuración de Base de Datos](#3-configuración-de-base-de-datos)
4. [Configuración de Google Cloud](#4-configuración-de-google-cloud)
5. [Configuración de Document AI (Opcional)](#5-configuración-de-document-ai-opcional)
6. [Iniciar el Servidor](#6-iniciar-el-servidor)
7. [Primeros Pasos](#7-primeros-pasos)

---

## 1. Requisitos Previos

### Software Necesario

- **Python 3.11 o superior**
- **pip** (gestor de paquetes de Python)
- **Git**
- **PowerShell** (Windows) / **Terminal** (macOS/Linux)

### Cuentas y Credenciales

- Cuenta de Google Cloud Platform (GCP)
- Acceso a Cloud SQL (PostgreSQL)
- Archivo de credenciales JSON de GCP

---

## 2. Instalación Local

### 2.1. Clonar el Repositorio

```bash
git clone https://github.com/Toninobandolero/Residencias.git
cd Residencias
```

### 2.2. Instalar Dependencias

```bash
pip install -r requirements.txt
```

**Dependencias principales:**
- Flask - Framework web
- PyJWT - Autenticación con tokens
- psycopg2-binary - Conexión a PostgreSQL
- python-dotenv - Variables de entorno
- Werkzeug - Seguridad y utilidades
- google-cloud-storage - Almacenamiento de archivos
- google-cloud-documentai - Procesamiento de documentos (opcional)
- openpyxl - Exportación a Excel

---

## 3. Configuración de Base de Datos

### 3.1. Variables de Entorno

Crear archivo `.env` en la raíz del proyecto:

```env
# Base de Datos
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=tu-contraseña-segura
DB_PORT=5432

# Opción A: Cloud SQL Proxy (Recomendado)
DB_USE_PROXY=true
DB_HOST=127.0.0.1
CLOUD_SQL_CONNECTION_NAME=tu-proyecto:region:instancia
GOOGLE_APPLICATION_CREDENTIALS=archivo-credenciales.json

# Opción B: Conexión Directa
# DB_USE_PROXY=false
# DB_HOST=IP-PUBLICA-CLOUD-SQL

# Autenticación JWT
JWT_SECRET_KEY=clave-secreta-muy-segura-cambiar-en-produccion

# Super Admin (valores por defecto)
SUPER_ADMIN_EMAIL=admin@residencias.com
SUPER_ADMIN_PASSWORD=CambiarEstaContraseña123!

# Google Cloud Storage
GCS_BUCKET_NAME=nombre-bucket-documentos
GCS_PROJECT_ID=tu-proyecto-gcp
```

**⚠️ IMPORTANTE:**
- El archivo `.env` **NO se versiona** (está en `.gitignore`)
- **Nunca** compartas credenciales
- Usa contraseñas fuertes en producción

### 3.2. Opción A: Cloud SQL Proxy (Recomendado)

**Ventajas:**
- ✅ No necesitas autorizar IPs
- ✅ Funciona desde cualquier ubicación
- ✅ Conexión encriptada y segura
- ✅ Recomendado por Google Cloud

**Instalación Windows:**
```powershell
.\setup_cloud_sql_proxy.ps1
.\configurar_proxy_env.ps1
```

**Instalación macOS/Linux:**
```bash
# Descargar Cloud SQL Proxy
curl -o cloud-sql-proxy https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.8.0/cloud-sql-proxy.darwin.amd64
chmod +x cloud-sql-proxy
```

### 3.3. Opción B: Conexión Directa

Si prefieres conectar directamente (sin proxy):

1. Obtén la IP pública de tu máquina:
   ```bash
   python obtener_mi_ip.py
   ```

2. Autoriza tu IP en Cloud SQL:
   - Ve a Google Cloud Console
   - Cloud SQL → Tu instancia → Connections
   - Authorized networks → Add network
   - Agrega tu IP

3. Configura `.env`:
   ```env
   DB_USE_PROXY=false
   DB_HOST=34.155.185.9  # IP pública de Cloud SQL
   ```

### 3.4. Inicializar Base de Datos

**Crear esquema y tablas:**
```bash
python create_database.py
```

**Inicializar permisos del sistema:**
```bash
python inicializar_permisos.py
```

**Asignar permisos a roles:**
```bash
python asignar_permisos_director.py
```

---

## 4. Configuración de Google Cloud

### 4.1. Instalar gcloud CLI

**macOS:**
```bash
# Descargar instalador
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-darwin-arm.tar.gz

# Descomprimir
tar -xf google-cloud-cli-darwin-arm.tar.gz

# Instalar
./google-cloud-sdk/install.sh

# Reiniciar terminal
source ~/.zshrc  # o ~/.bashrc
```

**Windows:**
```powershell
.\instalar_gcloud.ps1
```

### 4.2. Autenticación

```bash
# Autenticarse con Google Cloud
gcloud auth login

# Configurar proyecto
gcloud config set project tu-proyecto-id

# Autenticación para aplicaciones
gcloud auth application-default login
```

### 4.3. Crear Bucket de Storage

```bash
# Crear bucket para documentos
gsutil mb -p tu-proyecto-id -c STANDARD -l europe-west9 gs://nombre-bucket/

# Configurar permisos públicos (si es necesario)
gsutil iam ch allUsers:objectViewer gs://nombre-bucket/
```

---

## 5. Configuración de Document AI (Opcional)

Document AI permite procesar facturas automáticamente.

### 5.1. Habilitar API

```bash
gcloud services enable documentai.googleapis.com
```

### 5.2. Crear Procesador

1. Ve a Google Cloud Console → Document AI
2. Crear procesador → Invoice Parser
3. Región: `europe-west9`
4. Copiar el ID del procesador

### 5.3. Configurar en Código

En `app.py`, actualizar:

```python
PROCESSOR_ID = "tu-processor-id"
PROJECT_ID = "tu-proyecto-id"
LOCATION = "europe-west9"
```

---

## 6. Iniciar el Servidor

### 6.1. Con Cloud SQL Proxy

**Windows:**
```powershell
.\start_server_with_proxy.ps1
```

**macOS/Linux:**
```bash
./start_server_with_proxy.sh
```

### 6.2. Sin Proxy

**Windows:**
```powershell
.\start_server.ps1
```

**macOS/Linux:**
```bash
./start_server.sh
```

### 6.3. Verificar

Abre el navegador en:
```
http://localhost:5001
```

**Nota:** El puerto es 5001 (no 5000) para evitar conflictos con AirPlay en macOS.

---

## 7. Primeros Pasos

### 7.1. Iniciar Sesión

**Credenciales por defecto:**
- Email: `admin@residencias.com`
- Contraseña: `CambiarEstaContraseña123!`

**⚠️ IMPORTANTE:** Cambia la contraseña inmediatamente después del primer login.

### 7.2. Cambiar Contraseña

```python
python reset_superadmin_password.py
```

O desde la aplicación:
1. Login
2. Mi Cuenta
3. Cambiar Contraseña

### 7.3. Crear Primer Usuario

1. Configuración → Usuarios
2. Click "+ Agregar Usuario"
3. Completar datos:
   - Email
   - Nombre y apellido
   - Rol (Administrador/Director/Personal)
   - Permisos específicos
   - Residencias de acceso
4. Guardar

### 7.4. Configurar Residencias

1. Configuración → Residencias
2. Verificar que existen "Las Violetas 1" y "Las Violetas 2"
3. Editar datos si es necesario:
   - Dirección
   - Teléfono
   - Email de contacto
   - Entidad fiscal asociada

### 7.5. Agregar Residentes

1. Módulo "Residentes"
2. Click "+ Agregar Residente"
3. Completar formulario:
   - **Datos básicos:** Nombre, apellidos, DNI, fecha de nacimiento
   - **Contacto:** Teléfono, email, dirección previa
   - **Familiares:** Contactos de emergencia
   - **Médicos:** Información sanitaria
   - **Habitación:** Número y tipo
   - **Económicos:** Método de pago, descuentos
4. Guardar

### 7.6. Gestionar Personal

1. Módulo "Personal"
2. Click "+ Agregar Personal"
3. Completar:
   - Datos personales
   - Puesto y departamento
   - Turno de trabajo
   - Salario y forma de pago
4. Guardar

### 7.7. Crear Cobros

1. Módulo "Facturación"
2. Click "+ Agregar Cobro"
3. Seleccionar:
   - Residente
   - Mes y año
   - Monto
   - Concepto (opcional)
4. Guardar

### 7.8. Subir Documentos

1. Módulo "Documentación"
2. Click "+ Subir Documento"
3. Seleccionar:
   - Tipo de entidad (Residente/Proveedor/Personal)
   - Entidad específica
   - Categoría del documento
   - Archivo
4. Agregar descripción (opcional)
5. Subir

---

## 8. Comandos Útiles

### Desarrollo

```bash
# Reiniciar servidor
python app.py

# Ver logs en tiempo real
tail -f app.log

# Verificar base de datos
python diagnosticar_login.py

# Regenerar cobros históricos
python regenerar_cobros_historicos.py
```

### Base de Datos

```bash
# Backup de base de datos
python backup_database.py

# Verificar conexión
python db_connector.py

# Actualizar contraseña
python actualizar_contraseña.py
```

### Google Cloud

```bash
# Ver logs de Cloud Run
gcloud run services logs read violetas-app --project=tu-proyecto

# Ver estado del servicio
gcloud run services describe violetas-app --region=europe-west9

# Ejecutar deploy manual
gcloud run deploy
```

---

## 9. Estructura de Permisos

El sistema usa permisos granulares. Cada usuario puede tener combinaciones específicas:

### Tipos de Permisos

**Por módulo:**
- `leer:modulo` - Ver el módulo y sus datos
- `crear:modulo` - Crear nuevos registros
- `editar:modulo` - Modificar registros existentes
- `eliminar:modulo` - Eliminar registros

**Ejemplo para Residentes:**
- `leer:residente` - Ver lista y fichas de residentes
- `crear:residente` - Agregar nuevos residentes
- `editar:residente` - Modificar datos, dar de baja/alta
- `eliminar:residente` - Eliminar completamente

### Roles Predefinidos

**Administrador (id_rol=2):**
- Acceso TOTAL al sistema
- Puede crear otros administradores
- Gestiona usuarios y permisos

**Director (id_rol=3):**
- Gestión completa de su(s) residencia(s)
- Todos los permisos excepto configuración de usuarios

**Personal (id_rol=4):**
- Permisos limitados según necesidades
- Definidos al crear el usuario

**💡 Tip:** Los permisos son independientes del rol. Un Director puede tener permisos limitados si así se configura.

---

## 10. Solución de Problemas Comunes

### Error: "No se puede conectar a la base de datos"

**Solución:**
1. Verificar que Cloud SQL Proxy está corriendo
2. Verificar credenciales en `.env`
3. Verificar que la IP está autorizada (si usas conexión directa)

### Error: "Permission denied" en Google Cloud

**Solución:**
```bash
gcloud auth application-default login
gcloud auth login
```

### Error: "ModuleNotFoundError"

**Solución:**
```bash
pip install -r requirements.txt
```

### Puerto 5001 ya en uso

**Solución:**
```bash
# Encontrar proceso usando el puerto
lsof -i :5001

# Matar proceso
kill -9 <PID>

# O usar otro puerto
export PORT=5002
python app.py
```

### Para más problemas, consulta: [GUIA_TROUBLESHOOTING.md](GUIA_TROUBLESHOOTING.md)

---

## 11. Próximos Pasos

1. ✅ Sistema instalado y funcionando
2. 📖 Lee [GUIA_SEGURIDAD_PERMISOS.md](GUIA_SEGURIDAD_PERMISOS.md) para entender el sistema de permisos
3. 🚀 Lee [GUIA_DESPLIEGUE_CI_CD.md](GUIA_DESPLIEGUE_CI_CD.md) para desplegar a producción
4. 📚 Consulta [REFERENCIA_API.md](REFERENCIA_API.md) para integración con otros sistemas

---

## 📞 Soporte

Si encuentras problemas:

1. Revisa [GUIA_TROUBLESHOOTING.md](GUIA_TROUBLESHOOTING.md)
2. Verifica los logs: `tail -f app.log`
3. Consulta la documentación de Google Cloud
4. Contacta al administrador del sistema

---

**Última actualización:** Diciembre 2025
**Versión del sistema:** 2.0
