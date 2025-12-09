# 📚 Referencia de API - Sistema Violetas

## 📋 Tabla de Contenidos

1. [Autenticación](#autenticación)
2. [Endpoints de Residentes](#endpoints-de-residentes)
3. [Endpoints de Facturación](#endpoints-de-facturación)
4. [Endpoints de Proveedores](#endpoints-de-proveedores)
5. [Endpoints de Personal](#endpoints-de-personal)
6. [Endpoints de Documentos](#endpoints-de-documentos)
7. [Estructura de Datos](#estructura-de-datos)
8. [Scripts Útiles](#scripts-útiles)

---

## 🔐 Autenticación

### Login

**Endpoint:** `POST /api/v1/login`

**Request:**
```json
{
  "email": "admin@residencias.com",
  "password": "ContraseñaSegura123!"
}
```

**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "requiere_cambio_clave": false
}
```

**Response si requiere cambio de contraseña:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "requiere_cambio_clave": true,
  "mensaje": "Debes cambiar tu contraseña antes de continuar"
}
```

**Response (401 Unauthorized):**
```json
{
  "error": "Credenciales inválidas"
}
```

### Uso del Token

Todas las peticiones protegidas requieren el header:

```
Authorization: Bearer <token_jwt>
```

**⚠️ IMPORTANTE:** El token JWT **NO incluye** `id_residencia`. Solo contiene:

```json
{
  "id_usuario": 1,
  "id_rol": 1,
  "exp": 1732896000
}
```

**Motivo:** Los usuarios pueden tener acceso a múltiples residencias. Las residencias se cargan desde la tabla `usuario_residencia` en el middleware.

### Cambiar Contraseña

**Endpoint:** `POST /api/v1/usuario/cambio-clave`

**Headers:**
```
Authorization: Bearer <token>
```

**Request:**
```json
{
  "password_actual": "ContraseñaActual123!",
  "password_nuevo": "NuevaContraseña456!"
}
```

**Response (200 OK):**
```json
{
  "mensaje": "Contraseña actualizada exitosamente"
}
```

**Validaciones:**
- Contraseña actual debe ser correcta
- Contraseña nueva debe cumplir política de seguridad:
  - Mínimo 8 caracteres
  - Al menos una mayúscula
  - Al menos una minúscula
  - Al menos un número
  - Al menos un carácter especial
- Contraseña nueva debe ser diferente a la actual

---

---

## 👥 Endpoints de Residentes

### Listar Residentes

**Endpoint:** `GET /api/v1/residentes`

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "residentes": [
    {
      "id_residente": 1,
      "id_residencia": 1,
      "nombre": "Juan",
      "apellido": "Pérez",
      "documento_identidad": "12345678A",
      "fecha_nacimiento": "1945-03-15",
      "telefono": "612345678",
      "direccion": "Calle Ejemplo 123",
      "contacto_emergencia": "María Pérez",
      "telefono_emergencia": "698765432",
      "activo": true,
      "fecha_ingreso": "2020-01-15",
      "habitacion": "101",
      "costo_habitacion": 1200.00,
      "servicios_extra": "Fisioterapia",
      "medicaciones": "Insulina, Metformina",
      "peculiaridades": "Alergia a la penicilina",
      "metodo_pago_preferido": "transferencia",
      "fecha_creacion": "2025-11-29T10:00:00",
      "nombre_residencia": "Violetas 1"
    }
  ],
  "total": 1
}
```

### Obtener Residente

**Endpoint:** `GET /api/v1/residentes/<id_residente>`

**Response (200 OK):**
```json
{
  "id_residente": 1,
  "id_residencia": 1,
  "nombre": "Juan",
  "apellido": "Pérez",
  ...
}
```

**Response (404 Not Found):**
```json
{
  "error": "Residente no encontrado"
}
```

### Crear Residente

**Endpoint:** `POST /api/v1/residentes`

**Request:**
```json
{
  "nombre": "Juan",
  "apellido": "Pérez",
  "documento_identidad": "12345678A",
  "fecha_nacimiento": "1945-03-15",
  "telefono": "612345678",
  "direccion": "Calle Ejemplo 123",
  "contacto_emergencia": "María Pérez",
  "telefono_emergencia": "698765432",
  "fecha_ingreso": "2020-01-15",
  "habitacion": "101",
  "costo_habitacion": 1200.00,
  "servicios_extra": "Fisioterapia",
  "medicaciones": "Insulina, Metformina",
  "peculiaridades": "Alergia a la penicilina",
  "metodo_pago_preferido": "transferencia"
}
```

**Response (201 Created):**
```json
{
  "id_residente": 1,
  "message": "Residente creado exitosamente"
}
```

### Actualizar Residente

**Endpoint:** `PUT /api/v1/residentes/<id_residente>`

**Request:** (mismos campos que crear, todos opcionales)

**Response (200 OK):**
```json
{
  "message": "Residente actualizado exitosamente"
}
```

---

## 💰 Endpoints de Facturación

### Listar Cobros

**Endpoint:** `GET /api/v1/facturacion/cobros`

**Query Parameters:**
- `incluir_completados` (opcional): `true` para incluir cobros completados

**Response (200 OK):**
```json
{
  "cobros": [
    {
      "id_pago": 1,
      "id_residente": 1,
      "nombre_residente": "Juan Pérez",
      "monto": 1200.00,
      "fecha_pago": "2025-12-01",
      "fecha_prevista": "2025-12-01",
      "mes_pagado": "Diciembre 2025",
      "concepto": "Mensualidad",
      "metodo_pago": "transferencia",
      "estado": "pendiente",
      "es_cobro_previsto": true,
      "fecha_creacion": "2025-11-29T10:00:00"
    }
  ],
  "total": 1
}
```

### Crear Cobro

**Endpoint:** `POST /api/v1/facturacion/cobros`

**Request:**
```json
{
  "id_residente": 1,
  "monto": 1200.00,
  "fecha_pago": "2025-12-01",
  "mes_pagado": "Diciembre 2025",
  "concepto": "Mensualidad",
  "metodo_pago": "transferencia",
  "estado": "pendiente"
}
```

### Actualizar Cobro

**Endpoint:** `PUT /api/v1/facturacion/cobros/<id_pago>`

**Request:**
```json
{
  "estado": "completado",
  "fecha_pago": "2025-12-01",
  "metodo_pago": "transferencia"
}
```

### Marcar como Cobrado

**Endpoint:** `PUT /api/v1/facturacion/cobros/<id_pago>/marcar-cobrado`

**Request:**
```json
{
  "fecha_pago": "2025-12-01",
  "metodo_pago": "transferencia"
}
```

### Generar Cobros Previstos

**Endpoint:** `POST /api/v1/facturacion/cobros/generar-previstos`

**Descripción:** Genera automáticamente cobros previstos para todos los residentes activos según su método de pago preferido.

**Response (200 OK):**
```json
{
  "cobros_generados": 5,
  "message": "Cobros previstos generados exitosamente"
}
```

### Estadísticas de Cobros

**Endpoint:** `GET /api/v1/facturacion/cobros/estadisticas`

**Response (200 OK):**
```json
{
  "historico": [
    {
      "mes": "2025-10",
      "total": 12000.00,
      "cobros": 10
    }
  ],
  "estimaciones": [
    {
      "mes": "2025-12",
      "estimado": 15000.00,
      "residentes": 12
    }
  ]
}
```

---

## 🏢 Endpoints de Proveedores

### Listar Proveedores

**Endpoint:** `GET /api/v1/proveedores`

**Response (200 OK):**
```json
{
  "proveedores": [
    {
      "id_proveedor": 1,
      "id_residencia": 1,
      "nombre": "Limpieza ABC",
      "nif_cif": "B12345678",
      "direccion": "Calle Proveedor 123",
      "telefono": "912345678",
      "email": "info@limpiezaabc.com",
      "contacto": "Juan García",
      "tipo_servicio": "Limpieza",
      "activo": true,
      "observaciones": "Servicio semanal",
      "fecha_creacion": "2025-11-29T10:00:00"
    }
  ],
  "total": 1
}
```

### Crear Proveedor

**Endpoint:** `POST /api/v1/proveedores`

**Request:**
```json
{
  "nombre": "Limpieza ABC",
  "nif_cif": "B12345678",
  "direccion": "Calle Proveedor 123",
  "telefono": "912345678",
  "email": "info@limpiezaabc.com",
  "contacto": "Juan García",
  "tipo_servicio": "Limpieza",
  "activo": true,
  "observaciones": "Servicio semanal"
}
```

### Actualizar Proveedor

**Endpoint:** `PUT /api/v1/proveedores/<id_proveedor>`

### Listar Pagos a Proveedores

**Endpoint:** `GET /api/v1/facturacion/proveedores`

**Response (200 OK):**
```json
{
  "pagos": [
    {
      "id_pago": 1,
      "id_proveedor": 1,
      "nombre_proveedor": "Limpieza ABC",
      "concepto": "Servicio mensual",
      "monto": 500.00,
      "fecha_pago": "2025-12-01",
      "metodo_pago": "transferencia",
      "estado": "pendiente",
      "numero_factura": "FAC-2025-001",
      "es_estimacion": false,
      "fecha_creacion": "2025-11-29T10:00:00"
    }
  ],
  "total": 1
}
```

### Crear Pago a Proveedor

**Endpoint:** `POST /api/v1/facturacion/proveedores`

**Request:**
```json
{
  "id_proveedor": 1,
  "concepto": "Servicio mensual",
  "monto": 500.00,
  "fecha_pago": "2025-12-01",
  "metodo_pago": "transferencia",
  "estado": "pendiente",
  "numero_factura": "FAC-2025-001",
  "es_estimacion": false
}
```

---

## 👨‍💼 Endpoints de Personal

### Listar Personal

**Endpoint:** `GET /api/v1/personal`

**Response (200 OK):**
```json
{
  "personal": [
    {
      "id_personal": 1,
      "nombre": "María",
      "apellido": "González",
      "documento_identidad": "87654321B",
      "telefono": "623456789",
      "email": "maria@violetas.com",
      "cargo": "Enfermera",
      "activo": true,
      "fecha_contratacion": "2020-01-01",
      "fecha_creacion": "2025-11-29T10:00:00"
    }
  ],
  "total": 1
}
```

---

## 👥 Endpoints de Usuarios

### Crear Usuario (Solo Super Admin)

**Endpoint:** `POST /api/v1/usuarios`

**Headers:**
```
Authorization: Bearer <token>
```

**Permisos requeridos:** Solo super_admin puede crear usuarios

**Request:**
```json
{
  "email": "admin1@violetas.com",
  "password": "ContraseñaSegura123!",
  "id_rol": 2,
  "id_residencias": [1, 2],
  "nombre": "Administrador",
  "apellido": "Violetas"
}
```

**Response (201 Created):**
```json
{
  "id_usuario": 2,
  "email": "admin1@violetas.com",
  "id_rol": 2,
  "mensaje": "Usuario creado exitosamente. Requiere cambio de contraseña en primer login."
}
```

**Validaciones:**
- Email único
- Contraseña cumple política de seguridad
- Rol existe y está activo
- Al menos una residencia asignada
- Residencias existen y están activas

---

## 📄 Endpoints de Documentos

### Listar Documentos de Residente

**Endpoint:** `GET /api/v1/residentes/<id_residente>/documentos`

**Response (200 OK):**
```json
{
  "documentos": [
    {
      "id_documento": 1,
      "tipo_documento": "DNI",
      "nombre_archivo": "dni_juan_perez.pdf",
      "descripcion": "Copia del DNI",
      "fecha_subida": "2025-11-29T10:00:00",
      "url_archivo": "https://storage.googleapis.com/...",
      "tamaño_bytes": 245760,
      "tipo_mime": "application/pdf"
    }
  ],
  "total": 1
}
```

### Subir Documento

**Endpoint:** `POST /api/v1/residentes/<id_residente>/documentos`

**Request:** (multipart/form-data)
- `tipo_documento`: Tipo de documento (DNI, Informe médico, etc.)
- `descripcion`: Descripción opcional
- `archivo`: Archivo a subir

**Response (201 Created):**
```json
{
  "id_documento": 1,
  "message": "Documento subido exitosamente"
}
```

### Eliminar Documento

**Endpoint:** `DELETE /api/v1/documentos/<id_documento>`

**Response (200 OK):**
```json
{
  "message": "Documento eliminado exitosamente"
}
```

---

## 📊 Estructura de Datos

### Residente

```typescript
interface Residente {
  id_residente: number;
  id_residencia: number;
  nombre: string;
  apellido: string;
  documento_identidad?: string;
  fecha_nacimiento?: string; // YYYY-MM-DD
  telefono?: string;
  direccion?: string;
  contacto_emergencia?: string;
  telefono_emergencia?: string;
  activo: boolean;
  fecha_ingreso?: string; // YYYY-MM-DD
  habitacion?: string;
  costo_habitacion?: number;
  servicios_extra?: string;
  medicaciones?: string;
  peculiaridades?: string;
  metodo_pago_preferido?: string; // "transferencia" | "efectivo" | "tarjeta"
  fecha_creacion: string; // ISO 8601
  nombre_residencia?: string;
}
```

### Cobro

```typescript
interface Cobro {
  id_pago: number;
  id_residente: number;
  nombre_residente?: string;
  monto: number;
  fecha_pago?: string; // YYYY-MM-DD (null para previstos)
  fecha_prevista?: string; // YYYY-MM-DD
  mes_pagado?: string;
  concepto?: string;
  metodo_pago?: string;
  estado: string; // "pendiente" | "completado"
  es_cobro_previsto: boolean;
  fecha_creacion: string; // ISO 8601
}
```

### Proveedor

```typescript
interface Proveedor {
  id_proveedor: number;
  id_residencia: number;
  nombre: string;
  nif_cif?: string;
  direccion?: string;
  telefono?: string;
  email?: string;
  contacto?: string;
  tipo_servicio?: string;
  activo: boolean;
  observaciones?: string;
  fecha_creacion: string; // ISO 8601
}
```

### Pago a Proveedor

```typescript
interface PagoProveedor {
  id_pago: number;
  id_proveedor: number;
  nombre_proveedor?: string;
  concepto: string;
  monto: number;
  fecha_pago: string; // YYYY-MM-DD
  metodo_pago?: string;
  estado: string; // "pendiente" | "completado"
  numero_factura?: string;
  es_estimacion: boolean;
  fecha_creacion: string; // ISO 8601
}
```

---

## 🛠️ Scripts Útiles

### Scripts de Inicio

```powershell
# Iniciar con Cloud SQL Proxy (Recomendado)
.\start_server_with_proxy.ps1

# Iniciar sin proxy
.\start_server.ps1

# Reiniciar servidor
.\restart_server.ps1

# Detener servidor
.\stop_server.ps1
```

### Scripts de Configuración

```powershell
# Configurar Cloud SQL Proxy
.\setup_cloud_sql_proxy.ps1

# Configurar .env para proxy
.\configurar_proxy_env.ps1
```

### Scripts de Utilidades

```powershell
# Backup de base de datos
.\backup.ps1

# Obtener IP pública
python obtener_mi_ip.py

# Diagnosticar sistema
python diagnostico_sistema.py

# Probar conexión a BD
python test_conexion_bd.py

# Probar API de residentes
python test_residentes_api.py
```

### Scripts de Base de Datos

```python
# Crear esquema
python create_database.py

# Crear usuario
from db_utils import create_user
create_user("email@ejemplo.com", "password", id_rol=1, id_residencia=1)

# Verificar tablas
python list_tables.py
```

---

## 🔒 Códigos de Estado HTTP

- `200 OK` - Petición exitosa
- `201 Created` - Recurso creado exitosamente
- `400 Bad Request` - Datos inválidos
- `401 Unauthorized` - Token inválido o faltante
- `404 Not Found` - Recurso no encontrado
- `500 Internal Server Error` - Error del servidor

---

## ⚠️ Errores Comunes

### 401 Unauthorized
```json
{
  "error": "Token de autenticación requerido"
}
```
**Solución:** Incluir header `Authorization: Bearer <token>`

### 400 Bad Request
```json
{
  "error": "Datos JSON requeridos"
}
```
**Solución:** Verificar formato JSON y campos requeridos

### 500 Internal Server Error
```json
{
  "error": "Error interno del servidor"
}
```
**Solución:** Revisar logs del servidor Flask

---

## 📝 Notas Importantes

1. **Filtrado automático**: Todas las consultas filtran por residencias asignadas (o acceso total si super_admin)
2. **Validación**: Todos los endpoints validan entrada usando `validators.py`
3. **Tokens**: Expiran después de 24 horas
4. **Fechas**: Formato ISO 8601 (YYYY-MM-DD) o ISO 8601 con tiempo
5. **Montos**: Decimales con 2 decimales (ej: 1200.00)
6. **Multi-residencia**: Los usuarios pueden tener acceso a múltiples residencias
7. **Super Admin**: Acceso total a todas las residencias (bypass de permisos)

---

Para más información sobre configuración y solución de problemas, ver `GUIA_TECNICA.md`

