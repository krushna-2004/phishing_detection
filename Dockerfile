# Use slim Python base image
FROM python:3.11-slim

# Install OS-level dependencies for pyzbar and OpenCV
RUN apt-get update && apt-get install -y \
    build-essential \
    libzbar0 \
    libsm6 \
    libxext6 \
    libxrender1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy project
COPY . .

# Run migrations and start Gunicorn
CMD ["sh", "-c", "python manage.py migrate && gunicorn phishing_detection.wsgi:application --bind 0.0.0.0:$PORT"]
