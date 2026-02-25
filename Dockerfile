FROM cccs/assemblyline-v4-service-base:stable

ENV NODE_VERSION=18.x
ENV SERVICE_PATH=webcrack_service.WebcrackService
ENV SERVICE_USER=assemblyline

USER root

# Install Node.js from nodesource
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get update && \
    apt-get install -y \
    nodejs \
    npm \
    build-essential \
    libfuzzy-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create service directory
WORKDIR /opt/al_service

# Copy files and set permissions
COPY . .

# Create logs directory with proper permissions
RUN mkdir -p /opt/al_service/logs && \
    chown -R assemblyline:assemblyline /opt/al_service && \
    chmod -R 755 /opt/al_service && \
    chmod 777 /opt/al_service/logs

# Switch to assemblyline user for remaining operations
USER assemblyline

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install webcrack with verbose logging
RUN mkdir -p /opt/al_service/node_modules && \
    echo '{"name":"webcrack-service","private":true,"type":"module","dependencies":{"webcrack":"latest"}}' > package.json && \
    npm install --verbose 2>&1 | tee npm_install.log && \
    echo "Node modules directory:" && \
    ls -la node_modules && \
    echo "Webcrack installation:" && \
    ls -la node_modules/webcrack
