# 🔒 Seguridad del Repositorio

## ✅ Protección de Archivos Sensibles

Los siguientes archivos están protegidos por `.gitignore` y NO se suben a GitHub:

- `github-actions-key.json` - Clave de Service Account
- `residencias-*-*.json` - Credenciales de GCP  
- `*.service-account.json` - Service accounts
- `.env` - Variables de entorno
- `*.key.json` - Archivos de claves
- `*password*.sh`, `*secret*.sh` - Scripts con información sensible

## ⚠️ Problemas Corregidos

### Contraseñas en Scripts

**Problema identificado:** Scripts con contraseñas hardcodeadas.

**Solución aplicada:**
- ✅ Scripts actualizados para usar variables de entorno
- ✅ `.gitignore` mejorado para proteger scripts sensibles
- ✅ Documentación actualizada

**Acción requerida si había scripts con contraseñas en GitHub:**
1. Rotar las contraseñas expuestas
2. Actualizar los scripts corregidos en GitHub
3. Considerar limpiar historial de Git si es necesario

## ✅ Información Pública (Normal)

Esta información puede estar en el repositorio sin problemas:

- Project ID (no es secreto)
- Service Account emails (solo nombres, no claves)
- URLs públicas de servicios
- Nombres de secrets (solo nombres, no valores)

## 🛡️ Mejores Prácticas

1. ✅ Variables de entorno para credenciales
2. ✅ Secrets Manager de GCP para valores sensibles
3. ✅ Scripts usan parámetros o variables de entorno
4. ✅ No hay credenciales hardcodeadas en código

## 📋 Verificación de Seguridad

### Comandos útiles

```bash
# Buscar patrones sospechosos en código
grep -r "password.*=" --include="*.py" --include="*.sh" --include="*.ps1" . | grep -v "#\|TODO\|example"

# Verificar archivos JSON que no deberían estar en Git
git ls-files | grep -E "\.(json|key|pem|p12)$"

# Buscar tokens en historial
git log -p | grep -i "ghp_"
```

## 🔄 Rotar Credenciales Expuestas

Si encuentras credenciales expuestas:

1. **Rotar inmediatamente** la credencial expuesta
2. **Actualizar** en todos los servicios (Cloud SQL, Secret Manager, etc.)
3. **Revisar logs** de acceso para detectar actividad sospechosa
4. **Considerar** hacer el repositorio privado si es público

---

**Última revisión:** 2025-12-10
