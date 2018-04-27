#!/bin/bash

for dest in $(<scpnodes); do
	echo ${dest}
	echo "scp tor dir"
	scp -r tor4 -v ${dest}:
	#echo "scp nodedistro dir"
    #scp -r nodedistro -v ${dest}:
    #scp tor3.0/setup.sh -v ${dest}:tor3.0/
done