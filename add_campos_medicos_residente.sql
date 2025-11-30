-- Script para agregar campos médicos esenciales a la tabla residente
-- Campos imprescindibles para la gestión de residentes ancianos

ALTER TABLE residente 
ADD COLUMN IF NOT EXISTS grupo_sanguineo VARCHAR(10),
ADD COLUMN IF NOT EXISTS alergias TEXT,
ADD COLUMN IF NOT EXISTS diagnosticos TEXT,
ADD COLUMN IF NOT EXISTS restricciones_dieteticas TEXT,
ADD COLUMN IF NOT EXISTS nivel_dependencia VARCHAR(50),
ADD COLUMN IF NOT EXISTS movilidad VARCHAR(100),
ADD COLUMN IF NOT EXISTS medico_referencia VARCHAR(255),
ADD COLUMN IF NOT EXISTS telefono_medico VARCHAR(50);

-- Comentarios para documentación
COMMENT ON COLUMN residente.grupo_sanguineo IS 'Grupo sanguíneo del residente (A+, B-, O+, AB+, etc.)';
COMMENT ON COLUMN residente.alergias IS 'Lista de alergias conocidas (medicamentos, alimentos, etc.)';
COMMENT ON COLUMN residente.diagnosticos IS 'Enfermedades crónicas y diagnósticos médicos relevantes';
COMMENT ON COLUMN residente.restricciones_dieteticas IS 'Restricciones alimentarias (diabetes, hipertensión, disfagia, etc.)';
COMMENT ON COLUMN residente.nivel_dependencia IS 'Nivel de dependencia (Autónomo, Dependencia leve, Dependencia moderada, Dependencia severa)';
COMMENT ON COLUMN residente.movilidad IS 'Estado de movilidad y ayudas técnicas (Andador, Silla de ruedas, Cama, etc.)';
COMMENT ON COLUMN residente.medico_referencia IS 'Nombre del médico de referencia o centro de salud';
COMMENT ON COLUMN residente.telefono_medico IS 'Teléfono del médico de referencia o centro de salud';

