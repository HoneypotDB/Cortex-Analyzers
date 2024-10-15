FROM python:3
WORKDIR /worker
COPY . Honeypotdb
RUN test ! -e Honeypotdb/requirements.txt || pip install --no-cache-dir -r Honeypotdb/requirements.txt
ENTRYPOINT HoneypotDB/honeypotdb.py