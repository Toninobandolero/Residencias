"""
Módulo de validación de datos para el sistema Violetas.
Proporciona funciones de validación reutilizables para endpoints.
"""
import re
from datetime import datetime


def validate_email(email):
    """
    Valida formato de email, aceptando caracteres Unicode y dominios IDN (punycode).
    
    Acepta:
    - Caracteres Unicode en la parte local (ñ, acentos, etc.)
    - Dominios ASCII estándar
    - Dominios IDN en formato punycode (xn--...)
    - Ejemplo válido: contacto@xn--logroo-0wa.com (logroño.com)
    """
    if not email:
        return False, "El email es requerido"
    
    try:
        # Separar parte local y dominio
        if '@' not in email:
            return False, "Formato de email inválido"
        
        local, domain = email.rsplit('@', 1)
        
        # Validar parte local (puede contener caracteres Unicode)
        if not local or len(local) > 64:
            return False, "La parte local del email es inválida (máximo 64 caracteres)"
        
        # Validar que la parte local no tenga espacios ni caracteres prohibidos
        # Permitir: letras (incluyendo Unicode), números, puntos, guiones, guiones bajos, +
        # Usar regex Unicode para aceptar caracteres especiales del español
        if re.search(r'[\s<>\[\](){}]', local):
            return False, "La parte local del email contiene caracteres inválidos"
        
        # Validar dominio (puede ser ASCII estándar o punycode para IDN)
        if not domain or len(domain) > 253:
            return False, "El dominio del email es inválido (máximo 253 caracteres)"
        
        # Verificar que el dominio tenga al menos un punto
        if '.' not in domain:
            return False, "Formato de email inválido: el dominio debe tener al menos un punto"
        
        # Verificar TLD (última parte después del último punto)
        tld = domain.split('.')[-1]
        if len(tld) < 2:
            return False, "El dominio del email debe tener un TLD válido (mínimo 2 caracteres)"
        
        # Aceptar dominios en formato punycode (xn--...) o ASCII estándar
        # El dominio puede contener letras, números, guiones y puntos
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^xn--[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            return False, "Formato de dominio inválido"
        
    except Exception as e:
        return False, f"Formato de email inválido: {str(e)}"
    
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


def validate_personal_data(data, is_update=False):
    """Valida datos completos de personal/empleado."""
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
    if 'telefono' in data and data.get('telefono'):
        valid, error = validate_phone(data.get('telefono'), 'Teléfono', required=False)
        if not valid:
            errors.append(error)
    
    if 'email' in data and data.get('email'):
        # Validar formato de email si se proporciona (opcional)
        email = data.get('email')
        if email and email.strip():
            valid, error = validate_email(email)
            if not valid:
                errors.append(error)
    
    if 'cargo' in data and data.get('cargo'):
        valid, error = validate_text(data.get('cargo'), 'Cargo', min_length=1, max_length=100, required=False)
        if not valid:
            errors.append(error)
    
    if 'fecha_contratacion' in data and data.get('fecha_contratacion'):
        valid, error = validate_date(data.get('fecha_contratacion'), 'Fecha de contratación', required=False, allow_future=False)
        if not valid:
            errors.append(error)
    
    if 'documento_identidad' in data and data.get('documento_identidad'):
        valid, error = validate_text(data.get('documento_identidad'), 'Documento de identidad', min_length=1, max_length=50, required=False)
        if not valid:
            errors.append(error)
    
    return len(errors) == 0, errors


def validate_turno_extra_data(data, is_update=False):
    """Valida datos completos de turno extra."""
    errors = []
    
    # Campos requeridos
    if not is_update:
        if 'id_personal' not in data or data.get('id_personal') is None:
            errors.append("id_personal es requerido")
        else:
            valid, error = validate_number(data.get('id_personal'), 'id_personal', min_value=1, required=True)
            if not valid:
                errors.append(error)
        
        if 'fecha' not in data or not data.get('fecha'):
            errors.append("Fecha es requerida")
        else:
            valid, error = validate_date(data.get('fecha'), 'Fecha', required=True, allow_future=True)
            if not valid:
                errors.append(error)
        
        if 'hora_entrada' not in data or not data.get('hora_entrada'):
            errors.append("Hora de entrada es requerida")
        
        if 'hora_salida' not in data or not data.get('hora_salida'):
            errors.append("Hora de salida es requerida")
    else:
        # En actualización, solo validar si se proporcionan
        if 'id_personal' in data and data.get('id_personal') is not None:
            valid, error = validate_number(data.get('id_personal'), 'id_personal', min_value=1, required=False)
            if not valid:
                errors.append(error)
        
        if 'fecha' in data and data.get('fecha'):
            valid, error = validate_date(data.get('fecha'), 'Fecha', required=False, allow_future=True)
            if not valid:
                errors.append(error)
    
    # Validar formato de hora (HH:MM)
    if 'hora_entrada' in data and data.get('hora_entrada'):
        hora_entrada = data.get('hora_entrada')
        if not re.match(r'^([0-1][0-9]|2[0-3]):[0-5][0-9]$', hora_entrada):
            errors.append("Hora de entrada debe tener formato HH:MM (24 horas)")
    
    if 'hora_salida' in data and data.get('hora_salida'):
        hora_salida = data.get('hora_salida')
        if not re.match(r'^([0-1][0-9]|2[0-3]):[0-5][0-9]$', hora_salida):
            errors.append("Hora de salida debe tener formato HH:MM (24 horas)")
    
    # Validar que hora_salida sea posterior a hora_entrada
    if 'hora_entrada' in data and 'hora_salida' in data and data.get('hora_entrada') and data.get('hora_salida'):
        try:
            from datetime import datetime
            entrada = datetime.strptime(data.get('hora_entrada'), '%H:%M').time()
            salida = datetime.strptime(data.get('hora_salida'), '%H:%M').time()
            if salida <= entrada:
                errors.append("La hora de salida debe ser posterior a la hora de entrada")
        except ValueError:
            pass  # Ya se validó el formato arriba
    
    # Validar motivo si se proporciona
    if 'motivo' in data and data.get('motivo'):
        valid, error = validate_text(data.get('motivo'), 'Motivo', min_length=1, max_length=500, required=False)
        if not valid:
            errors.append(error)
    
    return len(errors) == 0, errors