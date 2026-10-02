# ==============================================================================
# PhishWise - Production Dockerfile (Debian-based Python 3.11 Slim)
# ==============================================================================
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable live log streaming
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# 1. Install Linux system libraries required for:
#    - OpenCV & EasyOCR: libgl1, libglib2.0-0
#    - WeasyPrint PDF Engine: libpango-1.0-0, libharfbuzz0b, libpangoft2-1.0-0, shared-mime-info
#    - Thai Fonts for PDF: fonts-thai-tlwg
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-thai-tlwg \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# 3. Copy project source code
COPY . .

# 4. Create necessary persistent directories
RUN mkdir -p /app/media /app/static /app/output

# 5. Expose application port
EXPOSE 8000

# 6. Container launch command:
#    - Run database migrations
#    - Seed initial articles (idempotent)
#    - Start high-performance Gunicorn WSGI server
CMD ["sh", "-c", "python manage.py migrate && python manage.py seed_articles && gunicorn core.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 120"]
