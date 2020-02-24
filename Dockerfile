FROM python:3-slim

COPY requirements.txt /usr/src/app/
COPY src/libraries /usr/src/app/src/libraries
COPY src/app.py /usr/src/app/src/
COPY src/__init__.py /usr/src/app/src/
COPY src/config_sample.py /usr/src/app/src/config.py
COPY third_party /usr/src/app/third_party

RUN apt-get update && \
    apt-get install build-essential -y && \
    pip3 install --no-cache-dir -r /usr/src/app/requirements.txt && \
    python3 -m pip install /usr/src/app/third_party/dsm-py-sdk

#RUN useradd -rm -d /home/appuser -s /bin/bash -g root -G sudo -u 1000 appuser && chown appuser -R /usr/src/app
RUN useradd -rm -d /home/appuser -s /bin/bash -g root -G sudo -u 1000 appuser

USER appuser

WORKDIR /usr/src/app

CMD ["python", "src/collector.py"]

