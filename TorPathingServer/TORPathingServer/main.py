from shared import *
from random import shuffle
import struct
import sys
import socket
from SocketServer import TCPServer, BaseRequestHandler
from Crypt.Crypt import Crypt
from Crypto.PublicKey import RSA

MAX_PATH_LENGTH = 3

"""
Simple server to store and distribute active TOR routers on the
network. Does not persist data, meaning that the list of active routers is
lost on restart.

To run: python main.py [port_num]
"""
class CustomTCPServer(TCPServer, object):
    def __init__(self, server_address, request_handler):
        super(CustomTCPServer, self).__init__(server_address, request_handler)
        self.timeout = 3
        self.request_queue_size = 10
        self.private_key = Crypt().generate_key()
        self.tor_routers = {}
        self._connections = 0

    def getUniqueId(self):
        i = self._connections
        self._connections += 1
        return i


class TCPHandler(BaseRequestHandler):
    def _output(self, message):
        print "id%d: %s" % (self._id, message)

    def _register_router(self, request):
        registration = struct.unpack("!I%ds" % DER_KEY_SIZE, request)
        self.server.tor_routers[self.client_address[0]] = registration

    def _unregister_router(self):
        self.server.tor_routers.pop(self.client_address[0], None)

    def _create_route(self):
        route = ""
        shuffled_keys = self.server.tor_routers.keys()
        shuffle(shuffled_keys)

        for i in range(min(len(shuffled_keys), MAX_PATH_LENGTH)):
            ip_addr = shuffled_keys[i]
            (port, pub_key) = self.server.tor_routers[ip_addr]
            route += socket.inet_aton(ip_addr) + struct.pack("!I%ds" % DER_KEY_SIZE, port, pub_key)

        self.request.sendall(self._crypt.sign_and_encrypt(route))

    def setup(self):
        self._crypt = Crypt(self.server.private_key)
        self._id = self.server.getUniqueId()

    def handle(self):
        self._output("Establishing connection with with %s, port %s" % self.client_address)
        request = self.request.recv(DER_KEY_SIZE)
        self.request.sendall(self.server.private_key.publickey().exportKey(format='DER'))
        self._crypt.setPublicKey(RSA.import_key(request))

        while True:
            request = self.request.recv(1024)
            if len(request) == 0:
                continue
            try:
                request = self._crypt.decrypt_and_auth(request)
                request_type = request[0]
                request = request[1:]

                if request_type == MSG_TYPES.REGISTER_SERVER:
                    self._output("--- Registering new router: " + self.client_address[0])
                    self._register_router(request)
                elif request_type == MSG_TYPES.DEREGISTER_SERVER:
                    self._output("--- Deregistering router: " + self.client_address[0])
                    self._unregister_router()
                elif request_type == MSG_TYPES.GET_ROUTE:
                    self._output("--- Creating route")
                    self._create_route()
                elif request_type == MSG_TYPES.CLOSE:
                    self._output("--- Client exiting connection")
                    return
            except:
                self._output("ERROR: Message authentication failed")
                return


def main():
    HOST = "0.0.0.0"
    try:
        PORT = int(sys.argv[1])
    except KeyError:
        print "Usage: python main.py <PORT>"
        sys.exit(1)
    server = CustomTCPServer((HOST, PORT), TCPHandler)
    print "\nRunning on port %d\n" % PORT
    server.serve_forever()

if __name__ == "__main__":
    main()
