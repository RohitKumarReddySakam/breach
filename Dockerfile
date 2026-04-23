FROM python:3.14-slim
WORKDIR /app
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends iputils-ping && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m -u 1000 breach && chown -R breach:breach /app
USER breach
EXPOSE 5003
ENV PYTHONUNBUFFERED=1
CMD ["gunicorn","--worker-class","eventlet","-w","1","--bind","0.0.0.0:5003","--timeout","180","wsgi:app"]
