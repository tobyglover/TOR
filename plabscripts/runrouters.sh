#!/bin/bash
node=$1
port=$2
path="../../TorPathingServer/TorPathingServer/public.pem"
commands="cd tor4/TorRouter/TorRouter;python2.7 main.py $node $port $path;"
parallel-ssh -h allnodes.txt -x "-t -t" -t 0 -i -l tufts_dogar_comp112 $commands 