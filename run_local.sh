#!/usr/bin/env bash

echo "Setting up..."
echo "Please enter password: "
sudo ./setup.sh > /dev/null 2>&1

echo "Starting Pathing Server..."
cd TorPathingServer/TorPathingServer
python main.py 8000 > /dev/null 2>&1 &
sleep 3

echo "Starting routers..."
cd ../../TorRouter/TorRouter
python main.py 127.0.0.1 8000 ../../TorPathingServer/TorPathingServer/public.pem > /dev/null 2>&1 &
python main.py 127.0.0.1 8000 ../../TorPathingServer/TorPathingServer/public.pem > /dev/null 2>&1 &
python main.py 127.0.0.1 8000 ../../TorPathingServer/TorPathingServer/public.pem > /dev/null 2>&1 &
sleep 3

echo "Starting client..."
cd ../../client
python main.py 7000 127.0.0.1 8000 ../TorPathingServer/TorPathingServer/public.pem > /dev/null 2>&1 &
sleep 3
echo "Client running on port 7000"
