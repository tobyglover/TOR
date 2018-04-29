from shared import *
import sys
import socket
from Crypto.PublicKey import RSA
from Crypt import Crypt
from os import urandom
import struct
import multiprocessing
import torrouterd
from random import choice

ROUTE_INFO_SIZE = struct.calcsize(ROUTE_STRUCT_FMT)


class PathingFailed(Exception):
    pass


class TORPathingServer(object):
    """
    TORPathingServer

    Wrapper around communication between the TOR pathing server and the clients or
    routers in the network. Supports sregistering and deregistering TOR routers
    and getting a route for a client in the network.

    args:
        server_ip (str): ip address of pathing server
        server_port (int): port number of the pathing server
    """

    def __init__(self, server_ip, server_port, server_pubkey=None):
        self._server_ip = server_ip
        self._server_port = server_port
        self._router_id = None
        self._private_key = Crypt().generate_key()
        self._server_pubkey = server_pubkey
        self._optimized_routes = None
        if self._server_pubkey is None:
            self._server_pubkey = get_server_public_key()

    def __del__(self):
        self.unregister()

    def _newconnection(self):
        return Connection(self._server_ip, self._server_port, self._private_key, self._server_pubkey)

    def _parse_route_node(self, data):
        enc_pkt, ip, port, pk, sid, sym_key = struct.unpack(ROUTE_STRUCT_FMT, data)
        ip = socket.inet_ntoa(ip)
        pk = RSA.import_key(pk)
        return enc_pkt, ip, port, pk, sid, sym_key

    def _parse_route(self, route_data):
        i = 0
        route = []
        while (i + 1) * ROUTE_INFO_SIZE <= len(route_data):
            data = route_data[i * ROUTE_INFO_SIZE:(i + 1) * ROUTE_INFO_SIZE]
            route.append(self._parse_route_node(data))
            i += 1
        return route

    def _start_daemon(self, privatekey):
        self._p = multiprocessing.Process(target=torrouterd.start, name="torrouterd",
                                          args=(self._server_ip, self._server_port, privatekey, self._router_id),
                                          kwargs={"server_pubkey": self._server_pubkey})
        self._p.daemon = True
        self._p.start()

    def _stop_daemon(self):
        if not self._p is None:
            self._p.terminate()

    """
    Registers a new TOR router with the pathing server

    args:
        port (int): port that the router is listening on
        privatekey (Crypto.PublicKey.RSA instance): private key for the router. Only the public key
            is sent

    returns: None
    """
    def register(self, port, privatekey):
        assert self._router_id is None, "Error: instance is already registered with server"
        conn = self._newconnection()
        conn.send(struct.pack("!cI%ds" % DER_KEY_SIZE, MSG_TYPES.REGISTER_SERVER, port,
                              privatekey.publickey().exportKey(format='DER')))
        self._router_id = conn.receive()
        self._start_daemon(privatekey)

    """
    Unregisters a TOR router from the pathing server. Note that this is done automatically when the
    object is garbage collected.

    returns: None
    """
    def unregister(self):
        if self._router_id is None:
            return
        conn = self._newconnection()
        conn.send(struct.pack("!c%ds" % len(self._router_id), MSG_TYPES.DEREGISTER_SERVER, self._router_id))
        self._router_id = None
        self._stop_daemon()

    """
    Gets a new TOR route from the pathing server.

    returns: a list of the routers to pass through. Each router is represented
        as a 3-tuple containing in order the ip address (str), port (int), and
        the router's public key (Crypto.PublicKey.RSA instance). No assumptions
        should be made about the length of the route
    """
    def get_route(self):
        conn = self._newconnection()
        conn.send(struct.pack("!c", MSG_TYPES.GET_ROUTE))
        route_data = conn.receive(4096)
        if len(route_data) == 0:
            raise PathingFailed

        return self._parse_route(route_data)

    def get_optimized_route(self, refresh=False, destination=None):
        destinations = ["Americas", "Europe", "Asia"]

        if self._optimized_routes is None or refresh:
            conn = self._newconnection()
            conn.send(MSG_TYPES.GET_ROUTE_OPTIMIZED)
            route_data = conn.receive(4096*3)
            if len(route_data) == 0:
                raise PathingFailed

            route_size = len(route_data) / 3
            routes = []
            for i in range(3):
                routes.append(self._parse_route(route_data[i * route_size:(i+1) * route_size]))

            self._optimized_routes = routes

        if destination is None or not destination in destinations:
            return choice(self._optimized_routes)
        else:
            for i in range(len(destinations)):
                if destination == destinations[i]:
                    return self._optimized_routes[i]


if __name__ == "__main__":
    server = TORPathingServer(sys.argv[1], int(sys.argv[2]))
    if len(sys.argv) == 4:
        server.get_optimized_route()
    else:
        server.register(2100, RSA.generate(2048))
        raw_input("press enter to quit")
