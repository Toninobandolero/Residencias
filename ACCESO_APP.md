# Cómo Acceder a la Aplicación

## Estado del Servidor

La aplicación Flask está corriendo en: **http://localhost:5000**

## Formas de Acceder

### 1. Health Check (Navegador)

Abre tu navegador y ve a:
```
http://localhost:5000/health
```

Deberías ver:
```json
{
  "service": "Violetas Backend API",
  "status": "ok",
  "timestamp": "..."
}
```

### 2. Login (Requiere herramienta de API)

El login es un endpoint POST que requiere enviar JSON. Puedes usar:

#### Opción A: Postman o Thunder Client (Recomendado)

1. **Postman:**
   - Descarga: https://www.postman.com/downloads/
   - Crea una nueva petición POST
   - URL: `http://localhost:5000/api/v1/login`
   - Headers: `Content-Type: application/json`
   - Body (raw JSON):
     ```json
     {
       "email": "admin@violetas1.com",
       "password": "admin123"
     }
     ```

2. **Thunder Client** (extensión de VS Code):
   - Instala la extensión en VS Code
   - Crea nueva petición POST
   - URL: `http://localhost:5000/api/v1/login`
   - Body: JSON con email y password

#### Opción B: PowerShell (Desde terminal)

```powershell
Invoke-WebRequest -Uri http://localhost:5000/api/v1/login `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"email":"admin@violetas1.com","password":"admin123"}' | 
  Select-Object -ExpandProperty Content
```

#### Opción C: cURL (Si tienes Git Bash o WSL)

```bash
curl -X POST http://localhost:5000/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@violetas1.com","password":"admin123"}'
```

### 3. Usar el Token JWT

Una vez que obtengas el token del login, úsalo en el header `Authorization`:

```
Authorization: Bearer <tu_token_aqui>
```

Ejemplo en PowerShell:
```powershell
$token = "tu_token_aqui"
Invoke-WebRequest -Uri http://localhost:5000/api/v1/tu-endpoint `
  -Method GET `
  -Headers @{"Authorization"="Bearer $token"}
```

## Endpoints Disponibles

- `GET /health` - Health check (público)
- `POST /api/v1/login` - Login (público)
- Cualquier otra ruta requiere autenticación JWT

## Credenciales de Prueba

- **Email:** admin@violetas1.com
- **Contraseña:** admin123
- **Rol:** Administrador
- **Residencia:** Violetas 1 (ID: 1)

## Nota

Esta es una **API REST** (backend), no tiene interfaz web. Para crear una interfaz web necesitarías un frontend (React, Vue, etc.) que consuma esta API.

