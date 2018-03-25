from random import shuffle
import struct
import sys
import socket
import SocketServer

MAX_PATH_LENGTH = 3
DER_KEY_SIZE = 294
tor_routers = {}


"""
Simple server to store and distribute active TOR routers on the
network. Does not persist data, meaning that the list of active routers is
lost on restart. Is also relatively unfriendly in a threaded environment.

To run: python main.py [port_num]
"""
class TCPHandler(SocketServer.BaseRequestHandler):
    def _register_router(self, request):
        (_, port, pub_key) = struct.unpack("!cI%ds" % DER_KEY_SIZE, request)
        tor_routers[self.client_address[0]] = (port, pub_key)

    def _unregister_router(self):
        tor_routers.pop(self.client_address[0], None)

    def _create_route(self):
        route = ""
        shuffled_keys = tor_routers.keys()
        shuffle(shuffled_keys)

        for i in range(min(len(shuffled_keys), MAX_PATH_LENGTH)):
            ip_addr = shuffled_keys[i]
            (port, pub_key) = tor_routers[ip_addr]
            route += socket.inet_aton(ip_addr) + struct.pack("!I%ds" % DER_KEY_SIZE, port, pub_key)

        self.request.sendall(route)

    def handle(self):
        request = self.request.recv(1024)
        request_type = ord(request[:1])

        if request_type == 1:
            print "--- Registering new router: " + self.client_address[0]
            self._register_router(request)
        elif request_type == 2:
            print "--- Deregistering router: " + self.client_address[0]
            self._unregister_router()
        elif request_type == 3:
            print "--- Creating route"
            self._create_route()


def main():
    HOST = "localhost"
    PORT = int(sys.argv[1])
    server = SocketServer.TCPServer((HOST, PORT), TCPHandler)
    print "\nRunning on port %d\n" % PORT
    server.serve_forever()

if __name__ == "__main__":
    main()
