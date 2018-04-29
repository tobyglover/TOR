#!/bin/bash

for dest in $(<httpsites.txt); do
	echo "START OF A TEST"
	./testoneurl.sh ${dest} 10 planetlab5.ie.cuhk.edu.hk 9033
done