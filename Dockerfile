FROM python:3.9-slim-buster

# Install nmap for active port scanning
RUN apt-get update && \
    apt-get install -y nmap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Set entrypoint
ENTRYPOINT ["python", "asm.py"]
CMD ["-h"]
