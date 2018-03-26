FROM python:2.7-alpine

ARG proj
ARG port
ARG pip
ARG pport

EXPOSE $port

RUN apk update
RUN apk add gcc g++ make libffi-dev openssl-dev

WORKDIR /$proj
COPY $proj ./$proj
COPY TorPathingServer /tmp/TorPathingServer
RUN python -m pip install /tmp/TorPathingServer/
RUN python -m pip install pycrypto

CMD python ./router/main.py $port $pip $pport