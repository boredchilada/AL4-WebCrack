ARG branch=stable
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH=webcrack_service.WebcrackService

USER root

# Install Node.js 20 and build deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    build-essential \
    libfuzzy-dev \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Prep workdir with correct ownership
RUN mkdir -p /opt/al_service && chown assemblyline:assemblyline /opt/al_service

# Install Python dependencies as assemblyline user
USER assemblyline
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && \
    rm -rf ~/.cache/pip

WORKDIR /opt/al_service

# Install webcrack beta
RUN mkdir -p /opt/al_service/node_modules && \
    echo '{"name":"webcrack-service","private":true,"type":"module"}' > package.json && \
    npm install --no-save webcrack@2.16.0-beta.1 2>&1 && \
    node -e "import('webcrack').then(m => console.log('webcrack loaded OK'))"

# Copy service code
COPY . .

USER root
RUN chown -R assemblyline:assemblyline /opt/al_service

USER assemblyline
