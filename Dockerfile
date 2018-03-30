FROM python:2.7-alpine

ARG proj
ARG path
ARG args
ARG port
ENV proj=${proj}
ENV path=${path}
ENV args=${args}
ENV port=${port}

EXPOSE $port

RUN apk update
RUN apk add gcc g++ make libffi-dev openssl-dev

COPY $proj ./$proj
COPY TorPathingServer /tmp/TorPathingServer
COPY Crypt /tmp/Crypt
RUN python -m pip install /tmp/TorPathingServer/
RUN python -m pip install /tmp/Crypt/
RUN python -m pip install pycryptodome
WORKDIR /$proj

#CMD python -m SimpleHTTPServer
CMD python $path $args --port $port
#CMD python -i
#CMD sh