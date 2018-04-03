#!/bin/bash

echo "" > all.log

for i in `seq 0 ${1}`;
do
    echo "CONTAINER ${i}" >> all.log
    echo >> all.log
    docker logs router${i}.cont &>> all.log
    echo >> all.log
    echo >> all.log
done
