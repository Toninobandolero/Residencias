"""
Módulo de validación de datos para el sistema Violetas.
Proporciona funciones de validación reutilizables para endpoints.
"""
import re
from datetime import datetime


def validate_email(email):
    """Valida formato de email."""
    if not email:
        return False, "El email es requerido"
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Formato de email inválido"
    if len(email) > 255:
        return False, "El email es demasiado largo (máximo 255 caracteres)"
    return True, None


def validate_text(text, field_name, min_length=0, max_length=None, required=True):
    """Valida texto genérico."""
    if required and (not text or text.strip() == ''):
        return False, f"{field_name} es requerido"
    if text and len(text.strip()) < min_length:
        return False, f"{field_name} debe tener al menos {min_length} caracteres"
    if max_length and text and len(text) > max_length:
        return False, f"{field_name} no puede exceder {max_length} caracteres"
    return True, None


def validate_number(value, field_name, min_value=None, max_value=None, required=True, allow_float=False):
    """Valida números."""
    if required and value is None:
        return False, f"{field_name} es requerido"
    if value is None:
        return True, None
    
    try:
        if allow_float:
            num_value = float(value)
        else:
            num_value = int(value)
    except (ValueError, TypeError):
        return False, f"{field_name} debe ser un número válido"
    
    if min_value is not None and num_value < min_value:
        return False, f"{field_name} debe ser mayor o igual a {min_value}"
    if max_value is not None and num_value > max_value:
        return False, f"{field_name} debe ser menor o igual a {max_value}"
    
    return True, None


def validate_date(date_string, field_name, required=True, allow_future=True, allow_past=True):
    """Valida formato de fecha (YYYY-MM-DD)."""
    if required and not date_string:
        return False, f"{field_name} es requerido"
    if not date_string:
        return True, None
    
    try:
        date_obj = datetime.strptime(date_string, '%Y-%m-%d')
        today = datetime.now().date()
        date_only = date_obj.date()
        
        if not allow_future and date_only > today:
            return False, f"{field_name} no puede ser una fecha futura"
        if not allow_past and date_only < today:
            return False, f"{field_name} no puede ser una fecha pasada"
        
        # Validar rango razonable (1900-2100)
        if date_obj.year < 1900 or date_obj.year > 2100:
            return False, f"{field_name} debe estar entre 1900 y 2100"
        
        return True, None
    except ValueError:
        return False, f"{field_name} debe tener formato YYYY-MM-DD"


def validate_phone(phone, field_name, required=False):
    """Valida formato de teléfono."""
    if not phone and not required:
        return True, None
    if required and not phone:
        return False, f"{field_name} es requerido"
    
    # Permitir números, espacios, guiones, paréntesis y +
    pattern = r'^[\d\s\-\+\(\)]+$'
    if not re.match(pattern, phone):
        return False, f"{field_name} contiene caracteres inválidos"
    if len(phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '').replace('+', '')) < 9:
        return False, f"{field_name} es demasiado corto"
    if len(phone) > 50:
        return False, f"{field_name} es demasiado largo"
    return True, None


def validate_residencia_id(id_residencia):
    """Valida que id_residencia sea 1 o 2."""
    if id_residencia is None:
        return False, "id_residencia es requerido"
    if id_residencia not in [1, 2]:
        return False, "id_residencia debe ser 1 (Violetas 1) o 2 (Violetas 2)"
    return True, None


def validate_monto(monto, field_name="monto", required=True):
    """Valida monto (decimal positivo)."""
    if required and monto is None:
        return False, f"{field_name} es requerido"
    if monto is None:
        return True, None
    
    try:
        monto_float = float(monto)
        if monto_float < 0:
            return False, f"{field_name} no puede ser negativo"
        if monto_float > 999999.99:
            return False, f"{field_name} es demasiado grande (máximo 999,999.99)"
        return True, None
    except (ValueError, TypeError):
        return False, f"{field_name} debe ser un número válido"


def validate_estado(estado, allowed_states=None):
    """Valida estado de cobro/pago."""
    if not estado:
        return False, "Estado es requerido"
    if allowed_states is None:
        allowed_states = ['pendiente', 'cobrado', 'pagado', 'cancelado']
    if estado not in allowed_states:
        return False, f"Estado inválido. Debe ser uno de: {', '.join(allowed_states)}"
    return True, None


def validate_metodo_pago(metodo_pago, required=False):
    """Valida método de pago."""
    if not metodo_pago and not required:
        return True, None
    if required and not metodo_pago:
        return False, "Método de pago es requerido"
    
    allowed_methods = ['transferencia', 'remesa', 'metálico', 'bizum', 'cheque', 'otro']
    if metodo_pago.lower() not in allowed_methods:
        return False, f"Método de pago inválido. Debe ser uno de: {', '.join(allowed_methods)}"
    return True, None


def validate_residente_data(data, is_update=False):
    """Valida datos completos de residente."""
    errors = []
    
    # Campos requeridos
    if not is_update:
        valid, error = validate_text(data.get('nombre'), 'Nombre', min_length=2, max_length=255)
        if not valid:
            errors.append(error)
        
        valid, error = validate_text(data.get('apellido'), 'Apellido', min_length=2, max_length=255)
        if not valid:
            errors.append(error)
        
        valid, error = validate_residencia_id(data.get('id_residencia'))
        if not valid:
            errors.append(error)
    else:
        # En actualización, solo validar si se proporcionan
        if 'nombre' in data:
            valid, error = validate_text(data.get('nombre'), 'Nombre', min_length=2, max_length=255, required=False)
            if not valid:
                errors.append(error)
        
        if 'apellido' in data:
            valid, error = validate_text(data.get('apellido'), 'Apellido', min_length=2, max_length=255, required=False)
            if not valid:
                errors.append(error)
        
        if 'id_residencia' in data:
            valid, error = validate_residencia_id(data.get('id_residencia'))
            if not valid:
                errors.append(error)
    
    # Campos opcionales con validación
    if 'costo_habitacion' in data and data.get('costo_habitacion') is not None:
        valid, error = validate_monto(data.get('costo_habitacion'), 'Costo de habitación', required=False)
        if not valid:
            errors.append(error)
    
    if 'telefono' in data and data.get('telefono'):
        valid, error = validate_phone(data.get('telefono'), 'Teléfono', required=False)
        if not valid:
            errors.append(error)
    
    if 'telefono_emergencia' in data and data.get('telefono_emergencia'):
        valid, error = validate_phone(data.get('telefono_emergencia'), 'Teléfono de emergencia', required=False)
        if not valid:
            errors.append(error)
    
    if 'fecha_nacimiento' in data and data.get('fecha_nacimiento'):
        valid, error = validate_date(data.get('fecha_nacimiento'), 'Fecha de nacimiento', required=False)
        if not valid:
            errors.append(error)
    
    if 'fecha_ingreso' in data and data.get('fecha_ingreso'):
        valid, error = validate_date(data.get('fecha_ingreso'), 'Fecha de ingreso', required=False, allow_future=False)
        if not valid:
            errors.append(error)
    
    if 'metodo_pago_preferido' in data and data.get('metodo_pago_preferido'):
        valid, error = validate_metodo_pago(data.get('metodo_pago_preferido'), required=False)
        if not valid:
            errors.append(error)
    
    return len(errors) == 0, errors


def validate_cobro_data(data, is_update=False):
    """Valida datos de cobro."""
    errors = []
    
    if not is_update:
        # Creación: requeridos
        if 'id_residente' not in data or data.get('id_residente') is None:
            errors.append("id_residente es requerido")
        else:
            valid, error = validate_number(data.get('id_residente'), 'id_residente', min_value=1, required=True)
            if not valid:
                errors.append(error)
        
        valid, error = validate_monto(data.get('monto'), 'Monto', required=True)
        if not valid:
            errors.append(error)
        
        es_cobro_previsto = data.get('es_cobro_previsto', False)
        # Fecha prevista es opcional, pero si se proporciona debe ser válida
        if 'fecha_prevista' in data and data.get('fecha_prevista'):
            valid, error = validate_date(data.get('fecha_prevista'), 'Fecha prevista', required=False, allow_future=True)
            if not valid:
                errors.append(error)
        # Fecha de pago es opcional, pero si se proporciona debe ser válida
        if 'fecha_pago' in data and data.get('fecha_pago'):
            valid, error = validate_date(data.get('fecha_pago'), 'Fecha de pago', required=False, allow_future=False)
            if not valid:
                errors.append(error)
        
        # Validar concepto si se proporciona
        if 'concepto' in data and data.get('concepto'):
            valid, error = validate_text(data.get('concepto'), 'Concepto', min_length=1, max_length=500, required=False)
            if not valid:
                errors.append(error)
    
    # Validaciones opcionales
    if 'estado' in data and data.get('estado'):
        valid, error = validate_estado(data.get('estado'))
        if not valid:
            errors.append(error)
    
    if 'metodo_pago' in data and data.get('metodo_pago'):
        valid, error = validate_metodo_pago(data.get('metodo_pago'), required=False)
        if not valid:
            errors.append(error)
    
    if 'monto' in data and data.get('monto') is not None:
        valid, error = validate_monto(data.get('monto'), 'Monto', required=False)
        if not valid:
            errors.append(error)
    
    return len(errors) == 0, errors

