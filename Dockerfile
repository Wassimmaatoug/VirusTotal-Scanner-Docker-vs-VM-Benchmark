
FROM python:3.11-slim

# Metadonnees
LABEL maintainer="virustotal-sim"
LABEL description="VirusTotal Scanner — Docker vs VM Benchmark"

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dossier de travail
WORKDIR /app

# Dependances systeme (matplotlib a besoin de libGL sur slim)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgl1-mesa-glx \
        libglib2.0-0 \
        libsm6 \
        libxrender1 \
        libxext6 \
        libx11-6 \
        libfontconfig1 \
        libfreetype6 \
        gcc \
    && rm -rf /var/lib/apt/lists/*

# Dependances Python
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copie des sources
COPY simulator.py         .
COPY virustotal_scanner.py .
COPY vm_scanner.py        .
COPY docker_scanner.py    .
COPY live_dashboard.py    .
COPY live_terminal.py     .

# Copie du fichier .env s'il existe (optionnel)
# COPY .env .

# Port expose (pas obligatoire ici, mais bonne pratique)
EXPOSE 8888

# Commande par defaut — dashboard graphique
# Pour le terminal : docker run ... python live_terminal.py
CMD ["python", "live_dashboard.py"]
