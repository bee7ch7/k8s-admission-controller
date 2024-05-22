FROM python:3.12.2-alpine3.18

WORKDIR /app

COPY . /app/
RUN pip install -r requirements.txt

ENV FLASK_APP=main.py
ENV FLASK_DEBUG=1

# EXPOSE 8000
CMD ["flask", "run", "--host", "0.0.0.0", "--port", "443", "--cert", "/app/certs/tls.crt", "--key", "/app/certs/tls.key"]
