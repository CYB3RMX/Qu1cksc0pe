FROM python:3.7-alpine

WORKDIR /app
COPY requirements.txt requirements.txt
RUN apk add --update --no-cache g++ gcc libxslt-dev build-base
RUN apk --update add libxml2-dev libxslt-dev libffi-dev gcc musl-dev libgcc openssl-dev curl
RUN apk add jpeg-dev zlib-dev freetype-dev lcms2-dev openjpeg-dev tiff-dev tk-dev tcl-dev
RUN pip install --no-cache-dir --upgrade pip && \
    pip install setuptools

RUN pip3 install -r requirements.txt

COPY . .

ENTRYPOINT ["/app/qu1cksc0pe.py"]
