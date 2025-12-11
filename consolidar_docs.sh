#!/bin/bash

# Script para consolidar documentación
cd "/Volumes/SSD/Web/Violetas/Violetas app"

echo "📚 Consolidando documentación..."
echo ""

# Crear directorio temporal para archivos antiguos
mkdir -p docs_old

# 1. GUIA_COMPLETA.md - Instalación y Configuración
echo "1/4 Creando GUIA_COMPLETA.md..."

cat > GUIA_COMPLETA.md << 'EOF'
# 📚 Guía Completa - Instalación, Configuración y Uso

Guía completa para instalar, configurar y usar el Sistema de Gestión de Residencias Violetas.

## 📋 Tabla de Contenidos

1. [Requisitos Previos](#requisitos-previos)
2. [Instalación Local](#instalación-local)
3. [Configuración de Base de Datos](#configuración-de-base-de-datos)
4. [Configuración de Google Cloud](#configuración-de-google-cloud)
5. [Configuración de Document AI](#configuración-de-document-ai)
6. [Primeros Pasos](#primeros-pasos)

---

EOF

# Agregar contenido de archivos relacionados
cat GUIA_INSTALACION_Y_DESPLIEGUE.md >> GUIA_COMPLETA.md
echo -e "\n\n---\n\n" >> GUIA_COMPLETA.md
cat configurar_document_ai.md >> GUIA_COMPLETA.md

echo "✅ GUIA_COMPLETA.md creado"
echo ""

# Mostrar resumen
echo "📊 Resumen de consolidación:"
echo "- GUIA_COMPLETA.md: $(wc -l < GUIA_COMPLETA.md) líneas"
echo ""
echo "✅ Consolidación completada"

