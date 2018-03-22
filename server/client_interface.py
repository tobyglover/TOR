import socket
import struct
from Crypto.PublicKey import RSA

DER_KEY_SIZE = 294
ROUTE_INFO_SIZE = DER_KEY_SIZE + 8

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

    def _newconnection(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self._server_ip, self._server_port))
        return s

    def _send(self, socket, data):
        socket.sendall(data)

    def _receive(self, socket, size=1024):
        return socket.recv(size)

    def _parse_route_node(self, data):
        (ip, port, pub_key) = struct.unpack("!4sI%ds" % DER_KEY_SIZE, data)
        return (socket.inet_ntoa(ip), port, RSA.import_key(pub_key))

    def register(self, port, publicKey):
        conn = self._newconnection()
        self._send(conn, struct.pack("!cI%ds" % DER_KEY_SIZE, chr(1), port, publicKey.exportKey(format='DER')))
        conn.close()

    def unregister(self):
        conn = self._newconnection()
        self._send(conn, struct.pack("!c", chr(2)))
        conn.close()

    def get_route(self):
        conn = self._newconnection()
        self._send(conn, struct.pack("!c", chr(3)))
        route_data = self._receive(conn, ROUTE_INFO_SIZE * 3)

        i = 0
        route = []
        while (i + 1) * ROUTE_INFO_SIZE <= len(route_data):
            route.append(self._parse_route_node(route_data[i * ROUTE_INFO_SIZE:(i + 1) * ROUTE_INFO_SIZE + 1]))
            i += 1

        conn.close()
        return route
