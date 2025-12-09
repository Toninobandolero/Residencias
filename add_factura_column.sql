-- Añadir columna para almacenar la ruta del archivo de factura en pago_proveedor
ALTER TABLE pago_proveedor 
ADD COLUMN IF NOT EXISTS factura_blob_path VARCHAR(500);

-- Añadir comentario a la columna
COMMENT ON COLUMN pago_proveedor.factura_blob_path IS 'Ruta del archivo PDF de factura en Cloud Storage';

