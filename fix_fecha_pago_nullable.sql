-- Permitir NULL en fecha_pago para cobros previstos
-- Los cobros previstos no tienen fecha_pago porque aún no se han cobrado

ALTER TABLE pago_residente 
ALTER COLUMN fecha_pago DROP NOT NULL;

