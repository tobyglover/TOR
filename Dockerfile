FROM python:2.7-alpine

ARG proj
ARG path
ARG port
ARG args
ENV proj=${proj}
ENV path=${path}
ENV port=${port}
ENV args=${args}

EXPOSE $port

RUN apk update
RUN apk add gcc g++ make libffi-dev openssl-dev

COPY $proj ./$proj
WORKDIR /$proj
COPY TorPathingServer /tmp/TorPathingServer
COPY Crypt /tmp/Crypt
RUN python -m pip install /tmp/TorPathingServer/
RUN python -m pip install /tmp/Crypt/
RUN python -m pip install pycryptodome

#CMD python -m SimpleHTTPServer
CMD python $path $port $args