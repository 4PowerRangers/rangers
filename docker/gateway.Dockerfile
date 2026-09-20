FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app/src
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY environments ./environments
EXPOSE 8080
ENTRYPOINT ["python", "-B", "-m", "rangers.observe.gateway"]
