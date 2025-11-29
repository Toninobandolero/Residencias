# Solución para el Bloqueo de Push por Secretos en GitHub

## 📋 Problema

GitHub bloqueó el push porque detectó credenciales de Google Cloud Service Account en el historial del repositorio. Aunque el archivo ya fue eliminado en un commit posterior, GitHub lo detecta en el commit `10ca2b0`.

## ✅ Acciones Ya Realizadas

1. ✅ El archivo `residencias-479706-8c3bdbf8bbf8.json` ya fue eliminado del repositorio (commit `9691be3`)
2. ✅ El `.gitignore` ha sido actualizado para prevenir futuras subidas de archivos de credenciales
3. ✅ El archivo ya no está siendo rastreado por Git

## ⚠️ Problema Pendiente

El archivo todavía existe en el **historial de Git** (commit `10ca2b0`), por lo que GitHub lo sigue detectando.

## 🔧 Opciones de Solución

### Opción 1: Rotar las Credenciales (RECOMENDADO por Seguridad)

**Esta es la opción más segura** porque las credenciales ya fueron expuestas.

1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Navega a **IAM & Admin** > **Service Accounts**
3. Busca la cuenta: `residencias@residencias-479706.iam.gserviceaccount.com`
4. Ve a la pestaña **KEYS**
5. Elimina la clave existente (la que está comprometida)
6. Crea una nueva clave JSON
7. Descarga el nuevo archivo JSON
8. Reemplaza el archivo local `residencias-479706-8c3bdbf8bbf8.json` con el nuevo
9. Actualiza tu archivo `.env` si es necesario

**Ventajas:**
- ✅ Las credenciales antiguas quedan invalidadas
- ✅ No necesitas reescribir el historial de Git
- ✅ Es la práctica más segura

### Opción 2: Eliminar del Historial Completo (Avanzado)

Si prefieres eliminar el archivo del historial completo de Git, necesitas reescribir el historial.

**⚠️ ADVERTENCIA:** Esto requiere hacer un `force push` y puede afectar a otros colaboradores si trabajan en equipo.

```bash
# Usar git filter-branch o BFG Repo-Cleaner para eliminar el archivo del historial
# Ejemplo con git filter-branch:
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch residencias-479706-8c3bdbf8bbf8.json" \
  --prune-empty --tag-name-filter cat -- --all

# Luego hacer force push (SOLO si trabajas solo o coordinaste con tu equipo)
git push origin --force --all
```

### Opción 3: Permitir Temporalmente (NO RECOMENDADO)

GitHub ofrece una opción para permitir temporalmente el push, pero **NO es recomendable** porque:
- ❌ Las credenciales siguen siendo públicas en el historial
- ❌ Cualquiera que clone el repositorio tendrá acceso a ellas

Si aún así quieres usar esta opción, visita el enlace proporcionado por GitHub en el error.

## 🔒 Prevención Futura

Para evitar que esto vuelva a ocurrir:

1. **Nunca agregues archivos de credenciales a Git**
   - El `.gitignore` ya está configurado para ignorar archivos JSON de credenciales
   
2. **Usa variables de entorno para credenciales**
   - Las credenciales deben estar solo en el archivo `.env` (que ya está en `.gitignore`)
   - En producción, usa los secretos de Google Cloud directamente

3. **Revisa antes de hacer commit**
   ```bash
   git status  # Revisa qué archivos vas a subir
   git diff    # Revisa los cambios
   ```

## 📝 Verificación

Para verificar que el archivo ya no está siendo rastreado:

```bash
git ls-files | findstr residencias
# No debería devolver ningún resultado
```

## 🔗 Recursos

- [Documentación de GitHub sobre Push Protection](https://docs.github.com/code-security/secret-scanning/working-with-secret-scanning-and-push-protection)
- [Rotar credenciales de Service Account en GCP](https://cloud.google.com/iam/docs/creating-managing-service-account-keys)

