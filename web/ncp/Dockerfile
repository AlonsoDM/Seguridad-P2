FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /srv/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libc6-dev \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt /srv/app/requirements.txt
RUN pip install --no-cache-dir -r /srv/app/requirements.txt

COPY app/app.py /srv/app/app.py
COPY config /srv/app/config
COPY app/auth.py /srv/app/app/auth.py
COPY app/db.py /srv/app/app/db.py
COPY app/factory.py /srv/app/app/factory.py
COPY app/settings.py /srv/app/app/settings.py
COPY app/converter /srv/app/app/converter
COPY app/routes /srv/app/app/routes
COPY app/services /srv/app/app/services
COPY app/static /srv/app/app/static
COPY app/templates /srv/app/app/templates
COPY readflag.c /srv/app/readflag.c
COPY flag.txt /srv/app/flag.txt

RUN useradd --create-home --shell /bin/bash appuser && \
    mkdir -p /srv/app/logs /srv/app/data /home/appuser/.jupyter && \
    chown -R appuser:appuser /home/appuser && \
    chown -R appuser:appuser /srv/app

RUN mv /srv/app/flag.txt /root/flag.txt && \
    chmod 600 /root/flag.txt && \
    chown root:root /root/flag.txt && \
    gcc -O2 /srv/app/readflag.c -o /readflag && \
    chown root:root /readflag && \
    chmod 4755 /readflag

COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 8000

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
