# Use an official Python image
FROM python:3.11-slim

# Install dependencies for opencv-python and pyzbar
RUN apt-get update && apt-get install -y \
    build-essential \
    libzbar0 \
    libglib2.0-0 \
    libsm6 \
    libxrender1 \
    libxext6 \
    && rm -rf /var/lib/apt/lists/*

# Set environment vars
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy project
COPY . .

# Run migrations and start server
CMD ["sh", "-c", "python manage.py migrate && gunicorn phishing_detection.wsgi:application --bind 0.0.0.0:$PORT"]
