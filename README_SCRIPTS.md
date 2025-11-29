# Scripts de Gestión del Servidor

## Cómo Ejecutar los Scripts

### En PowerShell

**IMPORTANTE:** En PowerShell siempre debes usar `.\` antes del nombre del script:

```powershell
# Reiniciar servidor
.\restart_server.ps1

# Detener servidor
.\stop_server.ps1

# Iniciar servidor
.\start_server.ps1
```

### Si aparece error de política de ejecución

Si PowerShell muestra un error sobre políticas de ejecución, ejecuta primero:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Luego intenta ejecutar el script de nuevo.

### Alternativa: Doble Clic

También puedes hacer **doble clic** en:
- `restart_server.ps1` (reinicia el servidor)
- `restart_server.bat` (reinicia el servidor - versión batch)
- `stop_server.ps1` (detiene el servidor)
- `start_server.ps1` (inicia el servidor)

### Desde el Explorador de Archivos

1. Abre el Explorador de Windows
2. Navega a la carpeta del proyecto
3. Haz clic derecho en `restart_server.ps1`
4. Selecciona "Ejecutar con PowerShell"

## Scripts Disponibles

### `restart_server.ps1`
- Detiene cualquier proceso de Python/Flask existente
- Inicia el servidor en una nueva ventana
- **Uso:** `.\restart_server.ps1`

### `stop_server.ps1`
- Solo detiene los procesos del servidor
- **Uso:** `.\stop_server.ps1`

### `start_server.ps1`
- Solo inicia el servidor (sin detener procesos anteriores)
- **Uso:** `.\start_server.ps1`

### `restart_server.bat`
- Versión batch (no requiere PowerShell)
- Doble clic para ejecutar

## Solución de Problemas

### Error: "no se reconoce como nombre de un cmdlet"
**Solución:** Usa `.\restart_server.ps1` en lugar de solo `restart_server.ps1`

### Error: "no se puede cargar porque la ejecución de scripts está deshabilitada"
**Solución:** Ejecuta:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### El servidor no se inicia
- Verifica que Python esté instalado: `python --version`
- Verifica que el archivo `.env` exista y tenga las credenciales correctas
- Verifica que todas las dependencias estén instaladas: `pip install -r requirements.txt`

