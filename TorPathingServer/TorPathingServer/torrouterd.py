#daemon for tor routers to report network info to the pathing server

import sys
import uuid
import time
import threading
import struct
import socket
from SocketServer import TCPServer, BaseRequestHandler
from client_interface import Connection
from Crypt import Crypt
from shared import *

class CustomTCPServer(TCPServer, object):
    def __init__(self, server_address, request_handler, router_private_key):
        super(CustomTCPServer, self).__init__(server_address, request_handler)
        self.timeout = 3
        self.request_queue_size = 10
        self.router_private_key = router_private_key
        self.conn_private_key = Crypt().generate_key()

    def _newconnection(self):
        return Connection(self._server_ip, self._server_port, self._private_key)

class TCPHandler(BaseRequestHandler):
    def _send(self, message):
        data = self._crypt.sign_and_encrypt(message)
        self.request.sendall(data)

    def setup(self):
        self._crypt = Crypt(self.server.private_key)
        self._id = self.server.getUniqueConnectionId()

    def handle(self):
        request = self.request.recv(DER_KEY_SIZE)

class Reporter(object):
    def __init__(self, server_ip, server_port, router_private_key, router_id, own_port):
        self._server_ip = server_ip
        self._server_port = server_port
        self._router_key = router_private_key
        self._router_id = router_id
        self._conn_key = Crypt().generate_key()
        self._register(own_port)

    def _newconnection(self):
        return Connection(self._server_ip, self._server_port, self._conn_key)

    def _register(self, own_port):
        conn = self._newconnection()
        conn.send(struct.pack("!c%dsI" % ROUTER_ID_SIZE, MSG_TYPES.REGISTER_DAEMON, self._router_id, own_port))

    def begin_heartbeat(self):
        t = threading.Thread(target=self._begin_heartbeat)
        t.daemon = True
        t.start()

    def _begin_heartbeat(self):
        i = 0
        while True:
            with open("test.out", "w") as f:
                f.write(str(i) + "\n")
            i += 1
            time.sleep(HEARTBEAT_INTERVAL_SEC)


def start(server_ip, server_port, router_private_key, router_id):
    server = CustomTCPServer(("0.0.0.0", 0), TCPHandler, router_private_key)
    port = server.server_address[1]
    r = Reporter(server_ip, server_port, router_private_key, router_id, port)
    r.begin_heartbeat()
    server.serve_forever()

def main():
    print "SHOULD NOT BE CALLED DIRECTLY. INTENDED FOR TESTING PURPOSED ONLY"
    start(sys.argv[1], int(sys.argv[2]), Crypt().generate_key(), uuid.uuid4().bytes)

if __name__ == "__main__":
    main()
