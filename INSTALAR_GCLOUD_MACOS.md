# 📥 Instalar Google Cloud SDK (gcloud) en macOS

Parece que `gcloud` no está instalado en tu Mac. Aquí tienes las opciones para instalarlo.

---

## 🍺 Método 1: Con Homebrew (Recomendado - Más Fácil)

Si tienes Homebrew instalado:

```bash
# Instalar Google Cloud SDK
brew install --cask google-cloud-sdk

# Después de instalar, inicializar gcloud
gcloud init
```

**Nota:** Si no tienes Homebrew, primero instálalo:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

---

## 📦 Método 2: Instalador Oficial (Alternativa)

### Paso 1: Descargar el instalador

```bash
# Descargar el instalador
curl https://sdk.cloud.google.com | bash

# O descargar manualmente desde:
# https://cloud.google.com/sdk/docs/install-sdk
```

### Paso 2: Reiniciar la terminal

Después de instalar, cierra y abre la terminal de nuevo, o ejecuta:

```bash
exec -l $SHELL
```

### Paso 3: Inicializar gcloud

```bash
gcloud init
```

---

## ✅ Verificar Instalación

Después de instalar, verifica que funciona:

```bash
# Verificar versión
gcloud --version

# Debería mostrar algo como:
# Google Cloud SDK 450.0.0
# ...
```

---

## 🔐 Inicializar y Autenticar

Una vez instalado, inicializa gcloud:

```bash
# Inicializar gcloud (te pedirá que te autentiques)
gcloud init

# O solo autenticarte sin inicializar proyecto completo
gcloud auth login
```

**Durante `gcloud init` te pedirá:**
1. ✅ Iniciar sesión en Google Cloud
2. ✅ Seleccionar o crear un proyecto (usa: `residencias-479706`)
3. ✅ Configurar región por defecto (usa: `europe-west9`)

---

## ⚙️ Configurar Proyecto Manualmente

Si ya iniciaste sesión pero necesitas configurar el proyecto:

```bash
# Establecer proyecto
gcloud config set project residencias-479706

# Establecer región
gcloud config set compute/region europe-west9

# Verificar configuración
gcloud config list
```

---

## 🔍 Si gcloud sigue sin funcionar después de instalar

### Verificar PATH

Verifica que el PATH incluye gcloud:

```bash
# Verificar si está instalado pero no en PATH
which gcloud

# Ver PATH actual
echo $PATH

# Si está en ~/google-cloud-sdk/bin, añádelo al PATH
echo 'export PATH="$HOME/google-cloud-sdk/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Ubicación común de instalación

Si instalaste con Homebrew, generalmente está en:
```
/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin/gcloud
```

Si instalaste manualmente, generalmente está en:
```
~/google-cloud-sdk/bin/gcloud
```

### Añadir al PATH manualmente

Edita tu archivo `~/.zshrc`:

```bash
# Abrir archivo de configuración
nano ~/.zshrc

# Añadir esta línea al final (ajusta la ruta si es diferente):
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

# Guardar (Ctrl + O, Enter, Ctrl + X)

# Recargar configuración
source ~/.zshrc
```

---

## 🚀 Comandos Rápidos Después de Instalar

Una vez que gcloud esté funcionando:

```bash
# 1. Autenticarse
gcloud auth login

# 2. Configurar proyecto
gcloud config set project residencias-479706

# 3. Verificar autenticación
gcloud auth list

# 4. Verificar proyecto
gcloud config get-value project

# 5. Ver estado del servicio Cloud Run
gcloud run services describe violetas-app \
  --region europe-west9 \
  --project residencias-479706
```

---

## 🆘 Solución de Problemas

### Error: "command not found: gcloud"

**Solución:**
1. Verifica que la instalación terminó completamente
2. Reinicia la terminal
3. Verifica el PATH con `echo $PATH`
4. Añade gcloud al PATH manualmente si es necesario

### Error: "You do not currently have an active account selected"

**Solución:**
```bash
gcloud auth login
```

### Error: "Project [PROJECT_ID] not found"

**Solución:**
```bash
# Ver proyectos disponibles
gcloud projects list

# Establecer proyecto correcto
gcloud config set project residencias-479706
```

---

## 📚 Recursos Adicionales

- **Documentación oficial:** https://cloud.google.com/sdk/docs/install
- **Guía de inicio rápido:** https://cloud.google.com/sdk/docs/quickstart
- **Comandos comunes:** https://cloud.google.com/sdk/gcloud/reference

---

## ✅ Checklist de Instalación

- [ ] Google Cloud SDK instalado
- [ ] `gcloud --version` funciona
- [ ] Autenticado con `gcloud auth login`
- [ ] Proyecto configurado: `residencias-479706`
- [ ] Puede ejecutar: `gcloud run services list`

---

**Después de instalar gcloud, podrás ejecutar todos los comandos del archivo `DIAGNOSTICO_GCP.md`.**
