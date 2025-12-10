# ✅ Pasos Después de Instalar gcloud

Ahora que tienes gcloud instalado, sigue estos pasos para configurarlo.

---

## 🔍 Paso 1: Verificar que gcloud funciona

Primero, asegúrate de que gcloud está funcionando:

```bash
gcloud --version
```

**Deberías ver algo como:**
```
Google Cloud SDK 450.0.0
...
```

Si aún no funciona, reinicia la terminal o ejecuta:
```bash
exec -l $SHELL
```

---

## 🔐 Paso 2: Autenticarse en Google Cloud

Necesitas iniciar sesión con tu cuenta de Google Cloud:

```bash
gcloud auth login
```

**Esto hará:**
1. Abrirá tu navegador
2. Te pedirá que inicies sesión con tu cuenta de Google
3. Te pedirá permisos para acceder a Google Cloud

**Si tienes múltiples cuentas**, selecciona la cuenta que tiene acceso al proyecto `residencias-479706`.

---

## ⚙️ Paso 3: Configurar el Proyecto

Una vez autenticado, configura el proyecto:

```bash
# Establecer proyecto
gcloud config set project residencias-479706

# Verificar que se configuró correctamente
gcloud config get-value project
```

**Debería mostrar:** `residencias-479706`

---

## ✅ Paso 4: Verificar Configuración

Verifica que todo esté bien configurado:

```bash
# Ver información de autenticación
gcloud auth list

# Ver configuración completa
gcloud config list
```

**Deberías ver:**
- Tu cuenta activa en `gcloud auth list`
- Proyecto: `residencias-479706` en `gcloud config list`

---

## 🚀 Paso 5: Verificar Acceso al Servicio Cloud Run

Ahora prueba acceder a tu servicio en Cloud Run:

```bash
# Ver información del servicio
gcloud run services describe violetas-app \
  --region europe-west9 \
  --project residencias-479706 \
  --format="table(status.url,status.latestReadyRevisionName)"
```

**Si funciona**, verás la URL de tu servicio.

**Si da error de permisos**, necesitarás verificar los permisos IAM (ver Paso 6).

---

## 🔐 Paso 6: Verificar Permisos (Opcional)

Si tienes problemas de acceso, verifica tus permisos:

```bash
# Ver proyectos a los que tienes acceso
gcloud projects list

# Ver información del proyecto
gcloud projects describe residencias-479706
```

---

## 📋 Comandos Rápidos para Verificar Todo

Copia y pega estos comandos uno por uno:

```bash
# 1. Verificar versión
gcloud --version

# 2. Autenticarse (si no lo has hecho)
gcloud auth login

# 3. Configurar proyecto
gcloud config set project residencias-479706

# 4. Verificar autenticación
gcloud auth list

# 5. Verificar proyecto
gcloud config get-value project

# 6. Ver servicio Cloud Run
gcloud run services describe violetas-app \
  --region europe-west9 \
  --project residencias-479706 \
  --format="value(status.url)"
```

---

## 🎯 Próximos Pasos

Una vez que gcloud esté configurado, puedes:

1. **Verificar la configuración completa de GCP:**
   - Revisa el archivo `DIAGNOSTICO_GCP.md`
   - Ejecuta los comandos de verificación

2. **Revisar logs de producción:**
   ```bash
   gcloud run services logs read violetas-app \
     --region europe-west9 \
     --project residencias-479706 \
     --limit 50
   ```

3. **Verificar secrets:**
   ```bash
   gcloud secrets list --project=residencias-479706
   ```

---

## 🆘 Si Tienes Problemas

### Error: "You do not currently have an active account selected"
```bash
gcloud auth login
```

### Error: "Project [PROJECT_ID] not found"
- Verifica que tienes acceso al proyecto
- Verifica que el proyecto ID es correcto: `residencias-479706`
- Ver tus proyectos: `gcloud projects list`

### Error: "Permission denied"
- Tu cuenta necesita permisos en el proyecto
- Contacta al administrador del proyecto para que te otorgue permisos

---

**¡Empieza con el Paso 1 y avanza paso a paso!**
