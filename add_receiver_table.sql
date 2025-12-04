-- Crear tabla de receivers (sociedades que gestionan las residencias)
-- Las sociedades son entidades fiscales que pueden gestionar una o más residencias
CREATE TABLE IF NOT EXISTS receiver (
    id_receiver SERIAL PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    nif_cif VARCHAR(50),
    direccion TEXT,
    telefono VARCHAR(50),
    email VARCHAR(255),
    activo BOOLEAN DEFAULT TRUE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla intermedia para relación muchos a muchos: residencias <-> receivers (sociedades)
CREATE TABLE IF NOT EXISTS residencia_receiver (
    id_residencia INTEGER NOT NULL,
    id_receiver INTEGER NOT NULL,
    fecha_asignacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activo BOOLEAN DEFAULT TRUE,
    PRIMARY KEY (id_residencia, id_receiver),
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia),
    FOREIGN KEY (id_receiver) REFERENCES receiver(id_receiver)
);

-- Añadir columna id_receiver a pago_proveedor
-- Esta columna indica qué sociedad (receiver) está pagando la factura
ALTER TABLE pago_proveedor 
ADD COLUMN IF NOT EXISTS id_receiver INTEGER REFERENCES receiver(id_receiver);

-- Crear índices para mejorar búsquedas
CREATE INDEX IF NOT EXISTS idx_pago_proveedor_receiver ON pago_proveedor(id_receiver);
CREATE INDEX IF NOT EXISTS idx_receiver_nombre ON receiver(nombre);
CREATE INDEX IF NOT EXISTS idx_residencia_receiver_residencia ON residencia_receiver(id_residencia);
CREATE INDEX IF NOT EXISTS idx_residencia_receiver_receiver ON residencia_receiver(id_receiver);

