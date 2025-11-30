# Iconos Médicos Minimalistas

Colección de iconos SVG minimalistas para la aplicación de gestión de residencias Violetas.

## Uso

Estos iconos son SVG puros que se pueden usar directamente en HTML o como fondo en CSS.

### Ejemplo 1: Directo en HTML
```html
<img src="/static/icons/medical/stethoscope.svg" alt="Estetoscopio" width="24" height="24">
```

### Ejemplo 2: Como icono inline
```html
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
  <!-- contenido del SVG -->
</svg>
```

### Ejemplo 3: En CSS
```css
.icon-medical {
  background-image: url('/static/icons/medical/stethoscope.svg');
  background-size: contain;
  background-repeat: no-repeat;
  width: 24px;
  height: 24px;
}
```

## Iconos Disponibles

- **stethoscope.svg** - Estetoscopio (personal médico, consultas)
- **medical-cross.svg** - Cruz médica (emergencias, salud)
- **pill.svg** - Medicamentos (medicación, farmacia)
- **heart-pulse.svg** - Corazón con pulso (signos vitales, salud)
- **hospital.svg** - Edificio hospitalario (residencia, instalaciones)
- **user-medical.svg** - Usuario médico (personal, profesionales)
- **calendar-medical.svg** - Calendario médico (citas, citas médicas)
- **clipboard-medical.svg** - Portapapeles médico (historial, documentos)
- **syringe.svg** - Jeringa (inyecciones, medicación)
- **file-medical.svg** - Archivo médico (documentos, historial)
- **activity.svg** - Actividad (monitoreo, signos vitales)
- **alert-circle.svg** - Alerta (advertencias, alertas médicas)
- **check-circle.svg** - Verificación (confirmación, completado)
- **users.svg** - Usuarios (personal, residentes)
- **home.svg** - Hogar (residencia, vivienda)
- **bed.svg** - Cama (habitaciones, residentes)
- **package.svg** - Paquete (suministros, medicamentos)

## Personalización

Todos los iconos usan `stroke="currentColor"`, lo que significa que heredarán el color del texto del elemento padre. Puedes cambiar el color modificando el CSS:

```css
.medical-icon {
  color: #667eea; /* Cambiará el color del icono */
}
```

## Estilo

- Diseño minimalista y limpio
- Líneas finas (stroke-width="2")
- Formato SVG escalable
- Compatible con todos los navegadores modernos

## Licencia

Estos iconos están diseñados específicamente para la aplicación Violetas y están disponibles para su uso dentro del proyecto.

