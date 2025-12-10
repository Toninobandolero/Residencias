# 🔧 Cómo Abrir PowerShell

## En Windows

### Método 1: Desde el Menú Inicio (Más Fácil)
1. Presiona la tecla **Windows** (o haz clic en el botón Inicio)
2. Escribe: `PowerShell`
3. Haz clic en **"Windows PowerShell"** o **"PowerShell"**

### Método 2: Desde Ejecutar
1. Presiona `Windows + R`
2. Escribe: `powershell`
3. Presiona **Enter**

### Método 3: Desde la Terminal
1. Presiona `Windows + X`
2. Selecciona **"Windows PowerShell"** o **"Terminal"**

### Método 4: Desde el Explorador de Archivos
1. Abre el Explorador de Archivos
2. Navega a la carpeta del proyecto
3. En la barra de direcciones, escribe: `powershell`
4. Presiona **Enter**

### Método 5: Desde el Terminal Integrado de VS Code/Cursor
- Si estás usando **VS Code** o **Cursor**:
  1. Presiona `` Ctrl + ` `` (acento grave, arriba de Tab)
  2. O ve a: `Terminal` → `New Terminal`
  3. En el dropdown de terminal, selecciona **"PowerShell"**

---

## En macOS

### Si tienes PowerShell instalado

#### Método 1: Desde Spotlight
1. Presiona `Cmd + Space`
2. Escribe: `pwsh` o `powershell`
3. Presiona **Enter**

#### Método 2: Desde Terminal
1. Abre **Terminal** (Aplicaciones → Utilidades → Terminal)
2. Escribe: `pwsh`
3. Presiona **Enter**

#### Método 3: Instalar PowerShell (si no lo tienes)
```bash
# Opción 1: Con Homebrew (recomendado)
brew install --cask powershell

# Opción 2: Descargar desde Microsoft
# Ve a: https://aka.ms/powershell-release?tag=stable
```

### Nota Importante para macOS
En macOS, los scripts `.ps1` pueden necesitar ajustes. Si prefieres usar la terminal nativa de macOS (bash/zsh), puedes ejecutar comandos directamente con `gcloud` sin PowerShell.

---

## Verificar que PowerShell está funcionando

Una vez abierto PowerShell, escribe:

```powershell
$PSVersionTable
```

Deberías ver información sobre la versión de PowerShell.

---

## Navegar a tu proyecto

Una vez en PowerShell, navega a la carpeta del proyecto:

```powershell
cd "C:\ruta\a\tu\proyecto"
# O en macOS:
cd "/ruta/a/tu/proyecto"
```

Para tu proyecto específico:

```powershell
# En Windows
cd "C:\Volumes\SSD\Web\Violetas\Violetas app"

# En macOS (aunque la ruta con "Volumes" sugiere macOS)
cd "/Volumes/SSD/Web/Violetas/Violetas app"
```

---

## Ejecutar Scripts PowerShell

Una vez en la carpeta del proyecto:

```powershell
# Ejecutar script de verificación
.\verificar_configuracion_gcp.ps1

# Si te da error de política de ejecución, primero ejecuta:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Alternativa: Usar Terminal Normal (macOS/Linux)

Si estás en macOS y prefieres no usar PowerShell, puedes ejecutar los comandos de `gcloud` directamente en tu terminal:

```bash
# Verificar autenticación
gcloud auth list

# Verificar proyecto
gcloud config get-value project

# Ver estado del servicio
gcloud run services describe violetas-app \
  --region europe-west9 \
  --project residencias-479706
```

También puedes revisar el archivo `DIAGNOSTICO_GCP.md` que contiene todos los comandos en formato bash.

---

## Resumen Rápido

**Windows:**
- `Windows + X` → PowerShell
- O busca "PowerShell" en el menú inicio

**macOS:**
- Abre Terminal → escribe `pwsh`
- O usa la terminal normal con comandos `gcloud`

**VS Code/Cursor:**
- `` Ctrl + ` `` → Selecciona PowerShell en el dropdown

---

¿En qué sistema operativo estás? Puedo darte instrucciones más específicas.
