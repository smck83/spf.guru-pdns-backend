FROM python:3-slim
LABEL maintainer="s@mck.la"
ENV MY_APP_PATH=/opt/checkspf

ARG SOA_SERIAL=2025080300
ENV SOA_SERIAL=${SOA_SERIAL}

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    && mkdir -p $MY_APP_PATH/data
# ADD run.py main.py kv.py spfcustom.py $MY_APP_PATH
COPY run.py main.py dbInsert.py spfGuruBackend.py $MY_APP_PATH/
RUN pip install fastapi uvicorn["standard"] pyspf py3dns dnspython redis cachetools aiocache aiohttp
WORKDIR $MY_APP_PATH/

ENTRYPOINT ["python3", "-u", "/opt/checkspf/run.py"]

EXPOSE 8000/tcp
