#!/bin/bash


for i in `seq 0 ${1}`;
do
#    echo ARGS="35.160.105.33 800${i}" PORT=808${i} CONT=${i}
    make build ARGS="35.160.105.33 8000" PORT=808${i}
    make juststart ARGS="35.160.105.33 800${i}" PORT=808${i} CONT=${i}
done