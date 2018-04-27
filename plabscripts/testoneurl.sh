#!/bin/bash
url=$1
max_times=$2
host=$3
port=$4
pubkey="tor4/TorPathingServer/TorPathingServer/public.pem"
SUMPTIME="0"
SUMWOPTIME="0"
BYTES=`curl -w %{size_download} -o /dev/null -s -x "" $url`
echo "$BYTES bytes"
for i in `seq 1 $max_times`;
do
	MYPORT=$((i + 9000))
	echo "port: $MYPORT"
	timeout -s 2 41 python tor4/client/main.py $MYPORT $host $port $pubkey &
	sleep 20

	echo "sending http request"
	PTIME=`curl -w %{time_total} -o /dev/null -s -x localhost:$MYPORT $url`
	WOPTIME=`curl -w %{time_total} -o /dev/null -s -x "" $url`
	
	PTIME="${PTIME/,/.}"
	WOPTIME="${WOPTIME/,/.}"
	echo "$i.......with tor: $PTIME seconds"
	echo "$i....without tor: $WOPTIME seconds"
	SUMPTIME=`echo "scale=5; $PTIME + $SUMPTIME" | bc`
	SUMWOPTIME=`echo "scale=5; $WOPTIME + $SUMWOPTIME" | bc`
	sleep 21
done

AVGPTIME=`echo "scale=5; $SUMPTIME / $max_times" | bc`
AVGWOPTIME=`echo "scale=5; $SUMWOPTIME / $max_times" | bc`
echo "Avg with tor: $AVGPTIME"
echo "Avg without tor: $AVGWOPTIME"
echo "$BYTES bytes"