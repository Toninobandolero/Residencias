# 🔒 Solución: Error de Secreto Detectado por GitHub

## Problema
GitHub está bloqueando el push porque detectó credenciales de Google Cloud Service Account en el historial de Git (commit `10ca2b0`).

## ✅ Solución Rápida (Recomendada)

### Opción 1: Permitir Temporalmente el Secreto

1. **Abre esta URL** (proporcionada en el error de GitHub):
   ```
   https://github.com/Toninobandolero/Residencias/security/secret-scanning/unblock-secret/36CHDPpGyBEuysbyrTehz0zDEMc
   ```

2. **Haz clic en "Allow secret"** para permitir temporalmente el push.

3. **Intenta el push nuevamente**:
   ```powershell
   git push -u origin main
   ```

4. **Después del push exitoso, limpia el historial**:
   ```powershell
   .\limpiar_historial.ps1
   git push origin main --force
   ```

### Opción 2: Limpiar el Historial Antes del Push

1. **Ejecuta el script de limpieza**:
   ```powershell
   .\limpiar_historial.ps1
   ```

2. **Verifica que el archivo fue removido**:
   ```powershell
   git log --all --oneline -- "residencias-479706-8c3bdbf8bbf8.json"
   ```
   (No debería mostrar ningún resultado)

3. **Haz force push**:
   ```powershell
   git push origin main --force
   ```

## ⚠️ Advertencias Importantes

- **Force push reescribe el historial**: Asegúrate de que nadie más esté trabajando en el repositorio.
- **El archivo ya está en `.gitignore`**: No se volverá a subir accidentalmente.
- **Las credenciales expuestas**: Considera rotar las credenciales de Google Cloud después de limpiar el historial.

## 🔄 Rotar Credenciales (Recomendado)

Después de limpiar el historial, es recomendable:

1. Ir a [Google Cloud Console](https://console.cloud.google.com/iam-admin/serviceaccounts)
2. Eliminar la clave antigua de la cuenta de servicio
3. Crear una nueva clave JSON
4. Actualizar el archivo local `residencias-479706-8c3bdbf8bbf8.json` con las nuevas credenciales

## 📝 Notas

- El archivo `residencias-479706-8c3bdbf8bbf8.json` ya está correctamente configurado en `.gitignore`
- El script `limpiar_historial.ps1` remueve el archivo de todo el historial de Git
- Después de limpiar, el archivo solo existirá localmente y no se subirá a GitHub

