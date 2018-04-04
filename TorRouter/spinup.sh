#!/bin/bash


for i in `seq 0 ${1}`;
do
#    echo ARGS="35.160.105.33 800${i}" PORT=808${i} CONT=${i}
    make build ARGS="34.216.100.202 8000" PORT=808${i}
    make juststart ARGS="34.216.100.202 800${i}" PORT=808${i} CONT=${i}
done
