# 🔑 Crear Token de GitHub con Permisos de Workflow

Guía para crear un token de GitHub con permisos necesarios para workflows.

## Pasos:

### 1. Ir a la página de tokens

**Ve directamente a:**
https://github.com/settings/tokens/new

### 2. Configurar el token

**Nombre:** `GitHub Actions - Workflow Deploy`

**Expiration:** Elige una duración (30, 60, 90 días, o personalizada)

**Selecciona los scopes:**
- ✅ `repo` (acceso completo a repositorios) - **IMPORTANTE: incluye workflows**

### 3. Generar y copiar

- Haz clic en "Generate token"
- **Copia el token inmediatamente** (solo se muestra una vez)

### 4. Usar el token para push

```bash
# Configurar remote con el nuevo token
git remote set-url origin https://TU_NUEVO_TOKEN@github.com/Toninobandolero/Residencias.git

# Hacer push
git push origin main

# Restaurar URL (opcional)
git remote set-url origin https://github.com/Toninobandolero/Residencias.git
```

---

## Alternativa: Push Manual

Si prefieres, puedes hacer el push manualmente:

1. **Desde tu terminal:**
   ```bash
   git push origin main
   ```
   
2. Cuando te pida credenciales:
   - **Username:** tu usuario de GitHub
   - **Password:** El nuevo token con permisos `workflow`

---

## Después del Push

Una vez que el workflow esté en GitHub:

1. Ve a: https://github.com/Toninobandolero/Residencias/actions
2. Deberías ver el workflow "Deploy to Cloud Run"
3. Puedes ejecutarlo manualmente o esperar al próximo push
