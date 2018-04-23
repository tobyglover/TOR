from shared import *
from random import shuffle
import uuid
import struct
import sys
import socket
from SocketServer import TCPServer, BaseRequestHandler
from Crypt import Crypt
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

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
        self.private_key = self._getPrivateKey()
        self.tor_routers = {}
        self.connection_tests = {}
        self._connections = 0
        self.rid = "\x00" * 8

    def _getPrivateKey(self):
        with open('private.pem', 'r') as f:
            return RSA.import_key(f.read())

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
        data = self._crypt.sign_and_encrypt(message)
        self.request.sendall(data)

    def _register_router(self, request):
        (port, pub_key) = struct.unpack("!I%ds" % DER_KEY_SIZE, request)
        self._output("Registering new router: %s:%d" % (self.client_address[0], port))
        router_id = uuid.uuid4().bytes
        self.server.tor_routers[router_id] = {"ip_addr": self.client_address[0],
                                              "port": port,
                                              "pub_key": pub_key}
        self.server.connection_tests[router_id] = {}
        self._send(router_id)

    def _register_daemon(self, request):
        (router_id, daemon_port) = struct.unpack("!%dsI" % ROUTER_ID_SIZE, request)
        if router_id in self.server.tor_routers:
            self.server.tor_routers[router_id]["daemon_port"] = daemon_port

    def _determine_test_router(self, from_router_id):
        for k in self.server.tor_routers.keys():
            if k != from_router_id and "daemon_port" in self.server.tor_routers[k]:
                return k
        return None

    def _test_connection(self, request):
        router_id = request
        to_router_id = self._determine_test_router(router_id)

        if to_router_id is None:
            self._send("NONE")
            return

        to_router = self.server.tor_routers[to_router_id]
        c = Crypt(public_key=self.server.private_key.publickey(), private_key=self.server.private_key)
        now = now_as_str()
        payload = c.sign_and_encrypt(now + router_id + to_router_id)

        self._send(struct.pack("!4sI", socket.inet_aton(to_router["ip_addr"]), to_router["daemon_port"]) + payload)

    def _connection_test_results(self, request):
        now = datetime.utcnow()
        c = Crypt(public_key=self.server.private_key.publickey(), private_key=self.server.private_key)
        header = c.decrypt_and_auth(request[:512])
        start_time = header[:TIME_STR_SIZE]
        from_router_id = header[TIME_STR_SIZE:TIME_STR_SIZE+ROUTER_ID_SIZE]
        to_router_id = header[TIME_STR_SIZE+ROUTER_ID_SIZE:]

        i = 1
        times = [datetime_from_str(start_time)]
        for router_id in [from_router_id, to_router_id]:
            router = self.server.tor_routers.get(router_id, None)
            if router is None:
                return
            c = Crypt(public_key=RSA.import_key(router["pub_key"]), private_key=self.server.private_key)
            times.append(datetime_from_str(c.decrypt_and_auth(request[i * 512:(i + 1) * 512])))

            i += 1
        times.append(now)

        for i in range(1, len(times)):
            if times[i] < times[i - 1]:
                # error, malicious or otherwise
                return

        latency = (times[2] - times[1]).total_seconds() * 1000

    def _unregister_router(self, request):
        router_id = request[:ROUTER_ID_SIZE]
        if self.server.tor_routers[router_id]["ip_addr"] == self.client_address[0]:
            details = self.server.tor_routers.pop(router_id, None)
            self.server.connection_tests.pop(router_id, None)
            if not details is None:
                self._output("Deregistering router: %s:%d" % (details["ip_addr"], details["port"]))

    def _create_route(self):
        route = ""
        shuffled_keys = self.server.tor_routers.keys()
        shuffle(shuffled_keys)

        for i in range(min(len(shuffled_keys), MAX_PATH_LENGTH)):
            details = self.server.tor_routers[shuffled_keys[i]]
            c = Crypt(public_key=RSA.import_key(details["pub_key"]), private_key=self.server.private_key, debug=True)
            sid = get_random_bytes(8)
            sym_key = get_random_bytes(16)
            enc_pkt = c.sign_and_encrypt("ESTB" + self.server.rid + sid + sym_key)
            route += struct.pack(ROUTE_STRUCT_FMT, enc_pkt, socket.inet_aton(details["ip_addr"]), details["port"], details["pub_key"], sid, sym_key)

        self._send(route)

    def setup(self):
        self._crypt = Crypt(self.server.private_key)
        self._id = self.server.getUniqueConnectionId()

    def handle(self):
        self._output("Establishing connection with with %s, port %s" % self.client_address, indent=False)
        request = self.request.recv(DER_KEY_SIZE)
        self._crypt.setPublicKey(RSA.import_key(request))

        while True:
            request = self.request.recv(4096)
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
            elif request_type == MSG_TYPES.REGISTER_DAEMON:
                self._output("Registering daemon for router")
                self._register_daemon(request)
            elif request_type == MSG_TYPES.TEST_CONNECTION:
                self._output("Testing connection")
                self._test_connection(request)
            elif request_type == MSG_TYPES.CONNECTION_TEST_RESULTS:
                self._output("Getting connection test results")
                self._connection_test_results(request)
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
