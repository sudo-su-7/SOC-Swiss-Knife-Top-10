FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

COPY ssk/ ./ssk/

# Default: web dashboard on 8000. Override CMD for CLI use.
EXPOSE 8000
CMD ["ssk", "web"]
