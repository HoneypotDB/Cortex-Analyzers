FROM python:3
WORKDIR /worker
COPY . HoneypotDB
RUN test ! -e HoneypotDB/requirements.txt || pip install --no-cache-dir -r HoneypotDB/requirements.txt
ENTRYPOINT HoneypotDB/honeypotdb.py
