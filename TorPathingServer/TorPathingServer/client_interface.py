from shared import *
import sys
import socket
import struct
from Crypto.PublicKey import RSA
from Crypt import Crypt
from random import shuffle
from os import urandom
import struct
import multiprocessing
import torrouterd

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

    def __del__(self):
        self.unregister()

    def _newconnection(self):
        return Connection(self._server_ip, self._server_port, self._private_key, self._server_pubkey)

    def _parse_route_node(self, data):
        enc_pkt, ip, port, pk, sid, sym_key = struct.unpack(ROUTE_STRUCT_FMT, data)
        ip = socket.inet_ntoa(ip)
        pk = RSA.import_key(pk)
        return enc_pkt, ip, port, pk, sid, sym_key

    def _start_daemon(self, privatekey):
        self._p = multiprocessing.Process(target=torrouterd.start, name="torrouterd", args=(self._server_ip, self._server_port, privatekey, self._router_id))
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
        conn.send(struct.pack("!cI%ds" % DER_KEY_SIZE, MSG_TYPES.REGISTER_SERVER, port, privatekey.publickey().exportKey(format='DER')))
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
        should be made about the length of the route (although it is currently 3
        or less)
    """
    def get_route(self):
        conn = self._newconnection()
        conn.send(struct.pack("!c", MSG_TYPES.GET_ROUTE))
        route_data = conn.receive(4096)
        if len(route_data) == 0:
            raise PathingFailed
        i = 0
        route = []
        while (i + 1) * ROUTE_INFO_SIZE <= len(route_data):
            data = route_data[i * ROUTE_INFO_SIZE:(i + 1) * ROUTE_INFO_SIZE]
            route.append(self._parse_route_node(data))
            i += 1

        return route


class TestTORPathingServer(object):
    def __init__(self, server_ip, server_port):
        self._server_ip = server_ip
        self._server_port = server_port
        self._router_id = None
        self.private_key = Crypt().generate_key()
        self.rid = urandom(16)
        self.routers = []

    def __del__(self):
        self.unregister()

    def register(self, port, public_key):
        self.routers.append(("127.0.0.1", port, public_key))

    def unregister(self):
        pass

    def get_route(self):
        route = []
        # print self.routers
        for r in self.routers[:3]:
            ip, port, pk = r
            c = Crypt(public_key=pk, private_key=self.private_key)
            sid = urandom(8)
            sym_key = urandom(16)
            enc_pkt = c.sign_and_encrypt("ESTB" + self.rid + sid + sym_key)
            # print "SIMKEYC", port, sym_key.encode("hex")
            # print "SID   C", port, sid.encode("hex")
            # print 'DATA', port, len("ESTB" + self.rid + sid + sym_key), ("ESTB" + self.rid + sid + sym_key).encode("hex")[:16], ("ESTB" + self.rid + sid + sym_key).encode("hex")[-16:]
            # print "r%d: Encrypting with %s Signing with %s - %s...%s:%s...%s (%dB)" % (port, pk.exportKey('DER').encode('hex')[70:86],
            #                                                         self.private_key.publickey().exportKey('DER').encode('hex')[70:86],
            #                                                         enc_pkt.encode('hex')[:16], enc_pkt.encode('hex')[-16:],
            #                                                         ("ESTB" + sid + sym_key).encode('hex')[:16],
            #                                                         ("ESTB" + sid + sym_key).encode('hex')[-16:],len(enc_pkt))
            route.append((enc_pkt, ip, port, pk, sid, sym_key))

        return route

if __name__ == "__main__":
    server = TORPathingServer(sys.argv[1], int(sys.argv[2]))
    server.register(2100, RSA.generate(2048))
    raw_input("press enter to quit")
