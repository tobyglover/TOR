# Tor Network

*_DISCLAIMER: THIS PROJECT HAS NOT BEEN FORMALLY VETTED AND SHOULD NOT BE CONSIDERED FULLY SECURE_*

## Purpose
Tor provides an anonymous, secure, and distributed connection to HTTP web resources.
Using _onion encryption_, Tor allows for anonymous and confidential connections
so that no individual can know who is accessing which website.

## Overview

Tor has three distinct components: the Tor routers,
the Tor client, and the Tor pathfinder server. The pathfinder server will
be responsible for returning a path of IP addresses and ports corresponding
to Tor routers, each with their own public key. The routers will register
their public keys along with the port they are listening on with the pathfinder
server, as well as route traffic through them to other routers/the Internet.
The client will determine the route to take after receiving the active nodes
from the pathfinder server and establish connections to the network.

# Setup

For all components, the packages must first be installed using the `setup.py` script:

```
./setup.py
```

_*Note: the script may need super user privaleges, in which case sudo must be used.*_


Afterwards, the individual components must be set up. First, the Pathfinding
Server must be started before any other components. Then, the Tor routers
can be added and removed at will. Finally, so long as the Pathfinding Server
and at least three Tor Routers are running, the Tor client can be run.


## Local Full-System Setup

To run all components locally for sanity-checks and testing, the `run_local.sh` and 
`kill_local.sh` may be used. `run_local.sh` spins up a pathing server, three routers, 
and a client on 127.0.0.1:7000.


## Tor Pathfinding Server Setup

The Pathfinding Server must be set up on a server with a static IP on a port
accessible through whatever firewalls may be set up. Alternatively, all components
can be run on localhost (127.0.0.1). To start the server, run:

```
nohup python ./TorPathingServer/TorPathingServer/main.py <PORT> &
```

Where `<PORT>` is the port to run the server on. Output will be redirected to
the file `nohup.out`.

To kill the Pathfinding Server, find the associated PID and run:

```
sudo kill <PID>
```


## Tor Router Setup

After the Tor Pathfinding Server is started, the Tor Routers can be set up.
The Routers are designed to run in Docker containers, and as such, Docker
must be installed and the Docker Daemon must be running.

To start the Docker Daemon, either use the graphical user interface, or run:

```
dockerd &
```

After Docker is running, the `spinup.sh` script can spin up multiple Routers.


```
cd ./TorRouter/

./spinup.sh <NUM>
```

Where `<NUM>` is the number (between 1 and 9) of routers to spin up.

_*Note: as of now, the IP and port of the Pathfinding Server are hardcoded into
the script, so they will need to be changed.*_

Similarly, the killing of the routers can be done with the `spindown.sh` script as
follows:

```
cd ./TorRouter/
./spindown.sh <NUM>
```

Where `<NUM>` is the number (between 1 and 9) of routers to spin down. It is best to
use the script and not manually kill the Docker containers, as the Routers otherwise
may not properly deregister themselves from the Pathfinding Server, corrupting
the network.


## Tor Client Setup

After the Tor Pathfinding Server and at least three Tor Routers have been set up,
the Tor Client is ready to be connected. The Client can be started with:

```
python ./client/main.py <PORT> <PF_IP> <PF_PORT> <PUBKEY_PATH>
```

Where `<PORT>` is the port to host the client proxy on and `<PF_IP>` and `<PF_PORT>`
are the IP and port of the Pathfinding Server and `<PUBKEY_PATH>` is the path to the 
public key of the Pathfinding Server.

After the Client is running and a path has been established, the local proxy
settings must be changed to aim at `127.0.0.1:<PORT>`.
