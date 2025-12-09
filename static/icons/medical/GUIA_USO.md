# Guía de Uso de Iconos Médicos

Esta carpeta contiene iconos SVG minimalistas diseñados específicamente para la aplicación de gestión de residencias Violetas.

## 📦 Iconos Disponibles

### Salud y Cuidado
- `stethoscope.svg` - Estetoscopio (personal médico, consultas)
- `medical-cross.svg` - Cruz médica (emergencias, salud general)
- `heart-pulse.svg` - Corazón con pulso (signos vitales, monitoreo)

### Medicación
- `pill.svg` - Píldora (medicamentos, farmacia)
- `syringe.svg` - Jeringa (inyecciones, tratamientos)
- `package.svg` - Paquete (suministros médicos)

### Instalaciones y Personal
- `hospital.svg` - Hospital/Residencia (instalaciones)
- `home.svg` - Hogar (residencia, vivienda)
- `bed.svg` - Cama (habitaciones, residentes)
- `user-medical.svg` - Usuario médico (personal sanitario)
- `users.svg` - Usuarios múltiples (personal, residentes)

### Documentación y Gestión
- `clipboard-medical.svg` - Portapapeles médico (historial clínico)
- `file-medical.svg` - Archivo médico (documentos)
- `calendar-medical.svg` - Calendario médico (citas, visitas)

### Estado y Alertas
- `check-circle.svg` - Verificación (completado, confirmado)
- `alert-circle.svg` - Alerta (advertencias importantes)
- `activity.svg` - Actividad (monitoreo, gráficas)

## 🎨 Cómo Usar

### Opción 1: Como imagen HTML (Más simple)
```html
<img src="/static/icons/medical/stethoscope.svg" 
     alt="Médico" 
     width="24" 
     height="24"
     style="color: #667eea;">
```

### Opción 2: SVG inline (Mejor para personalización)
```html
<svg xmlns="http://www.w3.org/2000/svg" 
     viewBox="0 0 24 24" 
     fill="none" 
     stroke="currentColor" 
     stroke-width="2"
     style="width: 24px; height: 24px; color: #667eea;">
  <!-- Copiar el contenido del archivo SVG aquí -->
</svg>
```

### Opción 3: En CSS como fondo
```css
.icon-medico {
  background-image: url('/static/icons/medical/stethoscope.svg');
  background-size: contain;
  background-repeat: no-repeat;
  background-position: center;
  width: 24px;
  height: 24px;
  display: inline-block;
}
```

## 🎨 Personalización de Color

Todos los iconos usan `stroke="currentColor"`, lo que significa que heredan el color del texto del elemento padre.

### Cambiar color con CSS
```css
/* Color específico */
.mi-icono {
  color: #667eea; /* Color primario Violetas */
}

/* O usando filtros CSS */
.mi-icono img {
  filter: brightness(0) saturate(100%) invert(49%) sepia(84%) 
          saturate(2417%) hue-rotate(217deg) brightness(94%) contrast(94%);
}
```

## 📏 Tamaños Recomendados

- **16px** - Iconos pequeños en botones, listas
- **24px** - Tamaño estándar (más común)
- **32px** - Iconos medianos en tarjetas
- **48px** - Iconos grandes en páginas principales

## 💡 Ejemplos Prácticos para Violetas

### En el menú de navegación
```html
<a href="/residentes" class="nav-item">
  <img src="/static/icons/medical/users.svg" width="20" height="20">
  <span>Residentes</span>
</a>
```

### En botones de acción
```html
<button class="btn-medico">
  <img src="/static/icons/medical/calendar-medical.svg" width="18" height="18">
  Agendar Cita
</button>
```

### En tarjetas de información
```html
<div class="info-card">
  <img src="/static/icons/medical/heart-pulse.svg" width="32" height="32">
  <h3>Signos Vitales</h3>
  <p>Monitoreo constante</p>
</div>
```

### Como indicador de estado
```html
<div class="status">
  <img src="/static/icons/medical/check-circle.svg" width="16" height="16">
  <span>Medicación administrada</span>
</div>
```

## 🔍 Ver Ejemplos Visuales

Abre `example.html` en tu navegador para ver todos los iconos y ejemplos de código.

## 📝 Notas

- Todos los iconos son **escalables** (SVG vectorial)
- **Minimalistas** - líneas finas, diseño limpio
- **Compatibles** con todos los navegadores modernos
- **Personalizables** - fácil cambiar color y tamaño
- **Sin dependencias** - no requieren librerías externas

## 🚀 Integración Rápida

Para usar en `index.html`:

1. Agrega la referencia al CSS (opcional):
```html
<link rel="stylesheet" href="/static/icons/medical/icons.css">
```

2. Usa los iconos directamente:
```html
<img src="/static/icons/medical/stethoscope.svg" width="24" height="24">
```

¡Listo! Los iconos están listos para usar en toda la aplicación.

