# Solución: Error de Sintaxis en Chrome

## Problema
Chrome muestra: `Uncaught SyntaxError: Unexpected token ';'`

## Causa
Chrome está parseando el HTML con credenciales en la URL (ej: `?email=...&password=...`), lo que causa errores de interpretación.

## Solución Implementada

### 1. Script de Limpieza Automática
Ahora el archivo `static/index.html` incluye un script al inicio que:
- Detecta si hay parámetros `email` o `password` en la URL
- Si los encuentra, hace un redirect completo con `window.location.replace()`
- Elimina COMPLETAMENTE esos parámetros de la URL

### 2. Protección Backend
El backend (`app.py`) rechaza cualquier intento de login con credenciales en URL query params.

## Pasos para Resolver (Usuario)

### Opción 1: Limpiar Caché de Chrome (Recomendado)
1. **Cerrar TODAS las pestañas y ventanas de Chrome**
2. **Abrir Chrome de nuevo**
3. **Limpiar caché completa:**
   - Presiona `Cmd+Shift+Delete` (Mac) o `Ctrl+Shift+Delete` (Windows)
   - Selecciona "Imágenes y archivos en caché"
   - Selecciona "Todo el tiempo"
   - Click en "Borrar datos"
4. **Acceder solo a:** `http://localhost:5001` (sin parámetros)
5. **Hacer login normalmente con el formulario**

### Opción 2: Modo Incógnito
1. Abre Chrome en modo incógnito: `Cmd+Shift+N` (Mac) o `Ctrl+Shift+N` (Windows)
2. Accede a `http://localhost:5001`
3. Haz login normalmente

### Opción 3: Hard Reload
1. Accede a `http://localhost:5001` (sin parámetros)
2. Presiona `Cmd+Shift+R` (Mac) o `Ctrl+Shift+R` (Windows)
3. Si sigue fallando, vuelve a la Opción 1

## ⚠️ IMPORTANTE: NO Accedas Nunca a URLs con Credenciales

**NUNCA uses URLs como:**
- ❌ `http://localhost:5001/?email=usuario@ejemplo.com&password=MiPassword123`
- ❌ `http://localhost:5001/?email=...&password=...`

**SIEMPRE usa:**
- ✅ `http://localhost:5001/`
- ✅ Usa el formulario de login para autenticarte

## Verificación
Después de seguir los pasos, deberías ver:
- ✅ La página carga sin errores
- ✅ El formulario de login aparece correctamente
- ✅ Puedes hacer login normalmente
- ✅ No hay errores de sintaxis en la consola de Chrome

## Soporte Técnico
Si el problema persiste después de limpiar la caché:
1. Verifica que no tengas extensiones de Chrome interfiriendo (desactívalas temporalmente)
2. Prueba en otro navegador (Firefox, Safari, Edge)
3. Reinicia el servidor: `.\restart_server.ps1`
