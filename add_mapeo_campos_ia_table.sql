-- Script para crear tabla de mapeo de campos de IA
-- Ejecutar este script en la base de datos PostgreSQL

CREATE TABLE IF NOT EXISTS mapeo_campos_ia (
    id_mapeo SERIAL PRIMARY KEY,
    campo_sistema VARCHAR(100) NOT NULL UNIQUE,
    campo_ia VARCHAR(100) NOT NULL,
    tipos_alternativos TEXT, -- JSON array con tipos alternativos
    activo BOOLEAN DEFAULT TRUE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insertar mapeos por defecto basados en el código actual
INSERT INTO mapeo_campos_ia (campo_sistema, campo_ia, tipos_alternativos, activo) VALUES
    ('numero_factura', 'invoice_id', '["invoice_number", "invoice_id_number"]', TRUE),
    ('fecha_pago', 'invoice_date', '["invoice_date_invoice"]', TRUE),
    ('fecha_vencimiento', 'due_date', '["invoice_date_due"]', TRUE),
    ('proveedor', 'supplier_name', '["supplier", "supplier_name_supplier_name"]', TRUE),
    ('proveedor_direccion', 'supplier_address', '["supplier_address_supplier_address"]', TRUE),
    ('proveedor_email', 'supplier_email', '["supplier_email_supplier_email"]', TRUE),
    ('proveedor_telefono', 'supplier_phone', '["supplier_phone_supplier_phone"]', TRUE),
    ('proveedor_nif', 'supplier_tax_id', '[]', TRUE),
    ('monto', 'total_amount', '["invoice_amount", "total_amount_due", "amount_due", "invoice_total"]', TRUE),
    ('impuestos', 'vat', '["tax_amount", "total_tax_amount", "vat_amount", "tax"]', TRUE),
    ('iva', 'vat', '["tax_amount", "total_tax_amount", "vat_amount", "tax"]', TRUE),
    ('base_imponible', 'net_amount', '["subtotal_amount", "subtotal", "line_item_amount", "amount"]', TRUE),
    ('concepto', 'line_item', '["line_item_description", "line_item_description_line_item_description"]', TRUE)
ON CONFLICT (campo_sistema) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_mapeo_campos_ia_campo_sistema ON mapeo_campos_ia(campo_sistema);
CREATE INDEX IF NOT EXISTS idx_mapeo_campos_ia_activo ON mapeo_campos_ia(activo);

