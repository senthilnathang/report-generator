FROM rust:1.75-slim-bookworm AS tui-builder

WORKDIR /app
COPY tui/ .
RUN cargo build --release && cp target/release/scan-tui /scan-tui

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh && \
    trivy --version

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh && \
    grype version

# Snyk
RUN curl -L https://static.snyk.io/cli/latest/snyk-linux -o /usr/local/bin/snyk && \
    chmod +x /usr/local/bin/snyk && \
    snyk --version

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY --from=tui-builder /scan-tui /usr/local/bin/scan-tui

RUN useradd -m scanner && chown -R scanner:scanner /app
USER scanner

ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
