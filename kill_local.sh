#!/usr/bin/env bash

kill $(ps | grep "main.py" | awk '{print $1}')
cd TorRouter/TorRouter
./rmdb.sh
