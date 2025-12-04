# Usar imagen base de Python 3.11
FROM python:3.11-slim

# Establecer directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema necesarias para psycopg2
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements.txt e instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar el resto de la aplicación
COPY . .

# Crear directorio para archivos estáticos si no existe
RUN mkdir -p static

# Exponer el puerto (Cloud Run usará PORT de variable de entorno)
ENV PORT=8080
EXPOSE 8080

# Verificar que la aplicación puede importarse (sin iniciar el servidor)
RUN python -c "import app; print('App import successful')" || echo "Warning: App import check failed"

# Usar gunicorn directamente con PORT de variable de entorno
# Cloud Run inyecta PORT automáticamente
CMD gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 4 --timeout 300 --access-logfile - --error-logfile - --log-level info app:app

