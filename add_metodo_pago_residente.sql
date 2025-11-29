-- Añadir campo metodo_pago_preferido a la tabla residente
-- Este campo almacena cómo prefiere pagar cada residente (transferencia, remesa, metálico, bizum, etc.)

ALTER TABLE residente
ADD COLUMN IF NOT EXISTS metodo_pago_preferido VARCHAR(50);

-- Comentario para documentar los valores posibles
COMMENT ON COLUMN residente.metodo_pago_preferido IS 'Método de pago preferido del residente: transferencia, remesa, metálico, bizum, etc.';

