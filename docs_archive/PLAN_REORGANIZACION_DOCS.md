# Plan de Reorganización de Documentación

## Estructura Actual (23 archivos)
Tenemos documentación dispersa en múltiples archivos pequeños.

## Estructura Propuesta (5 archivos principales)

### 1. **README.md** ✅ (Mantener)
   - Entrada principal al proyecto
   - Inicio rápido
   - Enlaces a documentación detallada

### 2. **GUIA_COMPLETA.md** (NUEVO - Consolidar)
   **Fusiona:**
   - GUIA_INSTALACION_Y_DESPLIEGUE.md
   - INSTALAR_GCLOUD_MACOS.md
   - PASOS_DESPUES_INSTALAR_GCLOUD.md
   - COMO_ABRIR_POWERSHELL.md
   - configurar_document_ai.md
   
   **Contenido:**
   - Instalación local (Windows/Mac/Linux)
   - Configuración de base de datos
   - Configuración de GCP
   - Configuración de Document AI
   - Primeros pasos

### 3. **GUIA_SEGURIDAD_PERMISOS.md** (NUEVO - Consolidar)
   **Fusiona:**
   - GUIA_SEGURIDAD_Y_PERMISOS.md
   - GUIA_SISTEMA_PERMISOS_FRONTEND.md
   - EJEMPLO_PERMISOS_SOLO_LECTURA.md
   - SEGURIDAD_REPOSITORIO.md
   - REVISION_PERMISOS_ENDPOINTS.md
   
   **Contenido:**
   - Arquitectura de seguridad
   - Sistema de autenticación
   - Roles y permisos (backend)
   - Permisos en frontend (funciones helper)
   - Ejemplos prácticos
   - Seguridad del repositorio

### 4. **GUIA_DESPLIEGUE_CI_CD.md** (NUEVO - Consolidar)
   **Fusiona:**
   - DESPLIEGUE_EXITOSO.md
   - ESTADO_DESPLIEGUE.md
   - CONFIGURAR_CI_CD.md
   - CREAR_TOKEN_WORKFLOW.md
   - .github/GITHUB_ACTIONS_SETUP.md
   
   **Contenido:**
   - Despliegue a Cloud Run
   - Configuración de GitHub Actions
   - CI/CD automático
   - Estado actual de producción
   - Comandos útiles

### 5. **GUIA_TROUBLESHOOTING.md** ✅ (Mantener y consolidar)
   **Fusiona:**
   - GUIA_TROUBLESHOOTING.md (base)
   - DIAGNOSTICO_GCP.md
   - SOLUCION_CONTAINER_IMPORT_FAILED.md
   - RESUMEN_DEBUGGING.md
   - SOLUCIONAR_ERROR_CONTRASEÑA_BD.md
   - SOLUCION_ERROR_CHROME.md
   
   **Contenido:**
   - Problemas comunes y soluciones
   - Diagnóstico de errores
   - Casos de estudio
   - Logs y debugging

### 6. **REFERENCIA_API.md** ✅ (Mantener)
   - Referencia completa de endpoints
   - Ejemplos de uso
   - Parámetros y respuestas

## Archivos a Eliminar (temporal/redundante)
- RESUMEN_CONSOLIDACION.md (temporal)

## Resultado Final
- 6 archivos principales bien organizados
- Fácil de navegar
- Menos duplicación
- Información lógicamente agrupada
