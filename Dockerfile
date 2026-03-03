# Dockerfile pro Tipovačku s Tesseract OCR
# Base image - Python 3.11 (slim = menší velikost)
FROM python:3.11-slim

# Nastav pracovní adresář v containeru
WORKDIR /app

# Install system dependencies (Tesseract OCR)
# apt-get update = aktualizuj seznam balíčků
# apt-get install = instaluj Tesseract OCR a češtinu
# rm -rf /var/lib/apt/lists/* = vyčisti cache (menší image)
RUN apt-get update && \
    apt-get install -y tesseract-ocr tesseract-ocr-ces && \
    rm -rf /var/lib/apt/lists/*

# Zkopíruj requirements.txt do containeru
COPY requirements.txt .

# Nainstaluj Python závislosti
RUN pip install --no-cache-dir -r requirements.txt

# Zkopíruj všechny soubory aplikace do containeru
COPY . .

# Koyeb používá PORT environment variable
# Default je 8000 pokud není nastavený
EXPOSE 8000

# Spusť aplikaci
# Koyeb automaticky nastaví $PORT
CMD ["python", "app2.py"]
