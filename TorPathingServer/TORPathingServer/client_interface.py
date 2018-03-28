from shared import *
import socket
import struct
from Crypto.PublicKey import RSA
import sys
sys.path.append('../../shared')
from Crypt import Crypt

ROUTE_INFO_SIZE = DER_KEY_SIZE + 8

class Connection(object):
    def __init__(self, server_ip, server_port, private_key):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((server_ip, server_port))
        self._crypt = Crypt(private_key)
        self._handshake(private_key)

    def __del__(self):
        self.close()

    def _handshake(self, private_key):
        self.send(private_key.publickey().exportKey(format='DER'))
        self._crypt.setPublicKey(RSA.import_key(self.receive(DER_KEY_SIZE)))

    def send(self, data):
        if (self._crypt.available()):
            data = self._crypt.sign_and_encrypt(data)
        self._socket.sendall(data)

    def receive(self, size=1024):
        data = self._socket.recv(size)
        if (self._crypt.available()):
            data = self._crypt.decrypt_and_auth(data)
        return data

    def close(self):
        self.send(MSG_TYPES.CLOSE)
        self._socket.close()

class PathingFailed(Exception):
    pass

"""
TORPathingServer

Wrapper around communication between the TOR pathing server and the clients or
routers in the network. Supports sregistering and deregistering TOR routers
and getting a route for a client in the network.

args:
    server_ip (str): ip address of pathing server
    server_port (int): port number of the pathing server
"""
class TORPathingServer(object):
    def __init__(self, server_ip, server_port):
        self._server_ip = server_ip
        self._server_port = server_port
        self._private_key = Crypt().generate_key()

    def _newconnection(self):
        return Connection(self._server_ip, self._server_port, self._private_key)

    def _parse_route_node(self, data):
        (ip, port, pub_key) = struct.unpack("!4sI%ds" % DER_KEY_SIZE, data)
        return (socket.inet_ntoa(ip), port, RSA.import_key(pub_key))

    """
    Registers a new TOR router with the pathing server

    args:
        port (int): port that the router is listening on
        publicKey (Crypto.PublicKey.RSA instance): public key for the router

    returns: None
    """
    def register(self, port, publicKey):
        conn = self._newconnection()
        conn.send(struct.pack("!cI%ds" % DER_KEY_SIZE, MSG_TYPES.REGISTER_SERVER, port, publicKey.exportKey(format='DER')))

    """
    Unregisters a TOR router from the pathing server

    returns: None
    """
    def unregister(self):
        conn = self._newconnection()
        conn.send(struct.pack("!c", MSG_TYPES.DEREGISTER_SERVER))

    """
    Gets a new TOR route from the pathing server.

    returns: a list of the routers to pass through. Each router is represented
        as a 3-tuple containing in order the ip address (str), port (int), and
        the router's public key (Crypto.PublicKey.RSA instance). No assumptions
        should be made about the length of the route (although it is currently 3
        or less)
    """
    def get_route(self):
        conn = self._newconnection()
        conn.send(struct.pack("!c", MSG_TYPES.GET_ROUTE))
        route_data = conn.receive(ROUTE_INFO_SIZE * 3)

        i = 0
        route = []
        while (i + 1) * ROUTE_INFO_SIZE <= len(route_data):
            route.append(self._parse_route_node(route_data[i * ROUTE_INFO_SIZE:(i + 1) * ROUTE_INFO_SIZE + 1]))
            i += 1

        return route
