-- ============================================================================
-- TABLA: articulo_factura
-- Descripción: Almacena las líneas de detalle/artículos de cada factura
-- ============================================================================

CREATE TABLE IF NOT EXISTS articulo_factura (
    id SERIAL PRIMARY KEY,
    
    -- Relación con el pago al proveedor
    pago_proveedor_id INTEGER NOT NULL REFERENCES pago_proveedor(id) ON DELETE CASCADE,
    
    -- Datos del artículo/línea
    descripcion TEXT NOT NULL,                    -- "Verduras frescas", "Gel de baño 500ml"
    cantidad DECIMAL(10, 2) DEFAULT 1,            -- 2.5 (kg), 3 (unidades)
    unidad VARCHAR(20),                           -- "kg", "unidades", "litros", "cajas"
    
    -- Importes
    precio_unitario DECIMAL(10, 2),               -- 15,50€ por unidad
    subtotal DECIMAL(10, 2) NOT NULL,             -- Precio sin IVA de esta línea
    iva_porcentaje INTEGER,                       -- 4, 10, 21
    iva_importe DECIMAL(10, 2),                   -- Importe del IVA de esta línea
    total DECIMAL(10, 2) NOT NULL,                -- Total con IVA de esta línea
    
    -- Categorización (para análisis futuro)
    categoria VARCHAR(100),                       -- "Alimentación", "Limpieza", "Medicamentos"
    subcategoria VARCHAR(100),                    -- "Verduras", "Productos desinfectantes"
    
    -- Metadatos
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Índices para consultas rápidas
    CONSTRAINT articulo_factura_importes_check CHECK (total >= 0 AND subtotal >= 0)
);

-- Índices para mejorar rendimiento
CREATE INDEX IF NOT EXISTS idx_articulo_factura_pago ON articulo_factura(pago_proveedor_id);
CREATE INDEX IF NOT EXISTS idx_articulo_factura_categoria ON articulo_factura(categoria);
CREATE INDEX IF NOT EXISTS idx_articulo_factura_descripcion ON articulo_factura(descripcion);

-- Comentarios para documentación
COMMENT ON TABLE articulo_factura IS 'Líneas de detalle (artículos) de cada factura de proveedor';
COMMENT ON COLUMN articulo_factura.descripcion IS 'Descripción del artículo o servicio';
COMMENT ON COLUMN articulo_factura.cantidad IS 'Cantidad comprada (puede ser decimal: 2.5 kg)';
COMMENT ON COLUMN articulo_factura.precio_unitario IS 'Precio por unidad sin IVA';
COMMENT ON COLUMN articulo_factura.categoria IS 'Categoría para análisis (puede ser NULL inicialmente)';
