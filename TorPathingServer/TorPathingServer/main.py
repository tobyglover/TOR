from shared import *
from random import shuffle
import uuid
import struct
import sys
import socket
from SocketServer import TCPServer, BaseRequestHandler
from Crypt import Crypt
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

    def getUniqueConnectionId(self):
        i = self._connections
        self._connections += 1
        return i


class TCPHandler(BaseRequestHandler):
    def _output(self, message, indent=True):
        if indent:
            message = "--- " + message
        print "id%d: %s" % (self._id, message)

    def _send(self, message):
        self.request.sendall(self._crypt.sign_and_encrypt(message))

    def _register_router(self, request):
        (port, private_key) = struct.unpack("!I%ds" % DER_KEY_SIZE, request)
        self._output("Registering new router: %s:%d" % (self.client_address[0], port))
        router_id = uuid.uuid4()
        self.server.tor_routers[router_id] = (self.client_address[0], port, private_key)
        self._send(router_id.bytes)

    def _unregister_router(self, request):
        router_id = uuid.UUID(bytes=request)
        if router_id in self.server.tor_routers and self.server.tor_routers[router_id][0] == self.client_address[0]:
            (ip_addr, port, _) = self.server.tor_routers.pop(router_id, None)
            self._output("Deregistering router: %s:%d" % (ip_addr, port))

    def _create_route(self):
        route = ""
        shuffled_keys = self.server.tor_routers.keys()
        shuffle(shuffled_keys)

        for i in range(min(len(shuffled_keys), MAX_PATH_LENGTH)):
            (ip_addr, port, pub_key) = self.server.tor_routers[shuffled_keys[i]]
            route += socket.inet_aton(ip_addr) + struct.pack("!I%ds" % DER_KEY_SIZE, port, pub_key)

        self._send(route)

    def setup(self):
        self._crypt = Crypt(self.server.private_key)
        self._id = self.server.getUniqueConnectionId()

    def handle(self):
        self._output("Establishing connection with with %s, port %s" % self.client_address, indent=False)
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
            except:
                self._output("ERROR: Message authentication failed")
                return

            if request_type == MSG_TYPES.REGISTER_SERVER:
                self._register_router(request)
            elif request_type == MSG_TYPES.DEREGISTER_SERVER:
                self._unregister_router(request)
            elif request_type == MSG_TYPES.GET_ROUTE:
                self._output("Creating route")
                self._create_route()
            elif request_type == MSG_TYPES.CLOSE:
                self._output("Client exiting connection")
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
