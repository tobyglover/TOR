# daemon for tor routers to report network info to the pathing server

import sys
import uuid
import time
import threading
import struct
import socket
from SocketServer import TCPServer, BaseRequestHandler
from Crypt import Crypt
from shared import *

CONN_KEY = Crypt().generate_key()


def append_current_time(payload, private_key, server_pubkey=None):
    if server_pubkey:
        c = Crypt(public_key=server_pubkey, private_key=private_key)
    else:
        c = Crypt(public_key=get_server_public_key(), private_key=private_key)
    return payload + c.sign_and_encrypt(now_as_str())


class CustomTCPServer(TCPServer, object):
    def __init__(self, server_address, request_handler, pathing_server_ip, pathing_server_port, router_private_key,
                 server_pubkey=None):
        super(CustomTCPServer, self).__init__(server_address, request_handler)
        self.timeout = 3
        self.request_queue_size = 10
        self.router_private_key = router_private_key
        self._pathing_server_ip = pathing_server_ip
        self._pathing_server_port = pathing_server_port
        self.server_pubkey = server_pubkey

    def _newconnection(self):
        return Connection(self._pathing_server_ip, self._pathing_server_port, CONN_KEY, self.server_pubkey)


class TCPHandler(BaseRequestHandler):
    def handle(self):
        payload = self.request.recv(2048)
        payload = MSG_TYPES.CONNECTION_TEST_RESULTS + append_current_time(payload, self.server.router_private_key,
                                                                          self.server.server_pubkey)
        conn = self.server._newconnection()
        conn.send(payload)


class Reporter(object):
    def __init__(self, server_ip, server_port, router_private_key, router_id, own_port, server_pubkey=None):
        self._server_ip = server_ip
        self._server_port = server_port
        self._router_key = router_private_key
        self._router_id = router_id
        self._server_pubkey = server_pubkey
        if self._server_pubkey is None:
            self._server_pubkey = get_server_public_key()

        self._register(own_port)

    def _newconnection(self):
        return Connection(self._server_ip, self._server_port, CONN_KEY, self._server_pubkey)

    def _register(self, own_port):
        conn = self._newconnection()
        conn.send(struct.pack("!c%dsI" % ROUTER_ID_SIZE, MSG_TYPES.REGISTER_DAEMON, self._router_id, own_port))

    def _test_connection(self, data):
        struct_fmt = "!4sI"
        info_size = struct.calcsize(struct_fmt)
        payload = data[info_size:]
        (ip_addr, port) = struct.unpack(struct_fmt, data[:info_size])
        ip_addr = socket.inet_ntoa(ip_addr)

        payload = append_current_time(payload, self._router_key, self._server_pubkey)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip_addr, port))
        s.sendall(payload)
        s.close()

    def begin_heartbeat(self):
        t = threading.Thread(target=self._begin_heartbeat)
        t.daemon = True
        t.start()

    def _begin_heartbeat(self):
        while True:
            conn = self._newconnection()
            conn.send(struct.pack("!c%ds" % ROUTER_ID_SIZE, MSG_TYPES.TEST_CONNECTION, self._router_id))
            data = conn.receive(1024)
            if data[:4] != "NONE":
                self._test_connection(data)

            conn.close()
            time.sleep(HEARTBEAT_INTERVAL_SEC)


def start(pathing_server_ip, pathing_server_port, router_private_key, router_id, server_pubkey=None):
    server = CustomTCPServer(("0.0.0.0", 0), TCPHandler, pathing_server_ip, pathing_server_port, router_private_key,
                             server_pubkey)
    port = server.server_address[1]
    r = Reporter(pathing_server_ip, pathing_server_port, router_private_key, router_id, port, server_pubkey)
    r.begin_heartbeat()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return


def main():
    print "SHOULD NOT BE CALLED DIRECTLY. INTENDED FOR TESTING PURPOSED ONLY"
    start(sys.argv[1], int(sys.argv[2]), Crypt().generate_key(), uuid.uuid4().bytes)


if __name__ == "__main__":
    main()
