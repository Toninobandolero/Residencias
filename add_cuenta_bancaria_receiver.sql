-- Agregar columna cuenta_bancaria a la tabla receiver
-- La cuenta bancaria pertenece a cada entidad fiscal (receiver), no a la residencia

ALTER TABLE receiver 
ADD COLUMN IF NOT EXISTS cuenta_bancaria VARCHAR(34);

-- Comentario para documentar el campo
COMMENT ON COLUMN receiver.cuenta_bancaria IS 'Cuenta bancaria (IBAN) de la entidad fiscal';

