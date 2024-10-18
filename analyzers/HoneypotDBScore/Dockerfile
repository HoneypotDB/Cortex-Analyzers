FROM python:3
WORKDIR /worker
COPY . HoneypotDBScore
RUN test ! -e HoneypotDBScore/requirements.txt || pip install --no-cache-dir -r HoneypotDBScore/requirements.txt
ENTRYPOINT HoneypotDBScore/honeypotdb.py
