FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock \
    && useradd --uid 10001 --create-home gateway \
    && mkdir /data && chown gateway:gateway /data
COPY gateway ./gateway
USER gateway
EXPOSE 8000
CMD ["python", "-m", "gateway.runtime"]
