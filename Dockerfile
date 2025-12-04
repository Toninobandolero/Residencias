# Usar imagen base de Python 3.11
FROM python:3.11-slim

# Establecer directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema necesarias para psycopg2
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements.txt e instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto de la aplicación
COPY . .

# Crear directorio para archivos estáticos si no existe
RUN mkdir -p static

# Exponer el puerto (Cloud Run usará PORT de variable de entorno)
ENV PORT=8080
EXPOSE 8080

# Usar gunicorn como servidor WSGI para producción
# Cloud Run inyectará PORT automáticamente, pero lo leemos de la variable de entorno
CMD exec gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 2 --timeout 120 --access-logfile - --error-logfile - app:app

