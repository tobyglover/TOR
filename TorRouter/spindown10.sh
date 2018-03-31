#!/bin/bash

#for i in `seq 0 9`;
#do
#    PID=$(docker exec -it router${i}.cont ps | grep 'TorRouter' | awk '{print $1}')
#    docker exec router${i}.cont kill -s SIGINT ${PID}
#done

for i in `seq 0 ${1}`;
do
    make clean CONT=${i}
done
