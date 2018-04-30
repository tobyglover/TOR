from shared import *
from structs import *
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
        self.routers = Routers()
        self.conn_graph = Graph()
        self._connections = 0
        self.rid = "\x00" * 8

    def _getPrivateKey(self):
        with open('private.pem', 'r') as f:
            return RSA.import_key(f.read())

    def getUniqueConnectionId(self):
        i = self._connections
        self._connections += 1
        return i

    def add_router(self, router):
        self.routers.add_router(router)
        self.conn_graph.add_router(router)

    def pop_router(self, router_id):
        router = self.routers.pop_router(router_id)
        self.conn_graph.remove_router(router)


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
        router = Router(self.client_address[0], port, pub_key)
        self.server.add_router(router)
        self._send(router.get_id())

    def _unregister_router(self, request):
        router_id = request[:ROUTER_ID_SIZE]
        router = self.server.routers.get_router(router_id)
        if not router is None and router.get_ip_addr() == self.client_address[0]:
            self.server.pop_router(router_id)
            self._output("Deregistering router: %s:%d" % (router.get_ip_addr(), router.get_port()))

    def _register_daemon(self, request):
        (router_id, daemon_port) = struct.unpack("!%dsI" % ROUTER_ID_SIZE, request)
        router = self.server.routers.get_router(router_id)
        if not router is None:
            router.set_daemon_port(daemon_port)

    def _test_connection(self, request):
        (router_id, daemon_port) = struct.unpack("!%dsI" % ROUTER_ID_SIZE, request)
        from_router = self.server.routers.get_router(router_id)
        if from_router is None:
            return
        elif from_router.get_daemon_port() is None:
            print daemon_port
            from_router.set_daemon_port(daemon_port)

        to_router = self.server.conn_graph.get_next_test(from_router)

        print self.server.conn_graph

        if to_router is None:
            self._send("NONE")
            return

        c = Crypt(public_key=self.server.private_key.publickey(), private_key=self.server.private_key)
        now = now_as_str()
        payload = c.sign_and_encrypt(now + router_id + to_router.get_id())

        self._send(struct.pack("!4sI", socket.inet_aton(to_router.get_ip_addr()), to_router.get_daemon_port()) + payload)

    def _connection_test_results(self, request):
        now = datetime.utcnow()
        c = Crypt(public_key=self.server.private_key.publickey(), private_key=self.server.private_key)
        header = c.decrypt_and_auth(request[:512])
        start_time = header[:TIME_STR_SIZE]
        from_router = self.server.routers.get_router(header[TIME_STR_SIZE:TIME_STR_SIZE+ROUTER_ID_SIZE])
        to_router = self.server.routers.get_router(header[TIME_STR_SIZE+ROUTER_ID_SIZE:])

        i = 1
        times = [datetime_from_str(start_time)]
        for router in [from_router, to_router]:
            if router is None:
                return
            c = Crypt(public_key=router.get_pub_key(parse=True), private_key=self.server.private_key)
            times.append(datetime_from_str(c.decrypt_and_auth(request[i * 512:(i + 1) * 512])))

            i += 1
        times.append(now)

        for i in range(1, len(times)):
            if times[i] < times[i - 1]:
                # error, malicious or otherwise
                return

        latency = (times[2] - times[1]).total_seconds() * 1000
        self.server.conn_graph.add_test_results(from_router.get_region(), to_router.get_region(), latency)

    def _enc_route(self, routers):
        route = ""

        for router in routers:
            c = Crypt(public_key=router.get_pub_key(parse=True), private_key=self.server.private_key, debug=True)
            sid = get_random_bytes(8)
            sym_key = get_random_bytes(16)
            enc_pkt = c.sign_and_encrypt("ESTB" + self.server.rid + sid + sym_key)
            route += struct.pack(ROUTE_STRUCT_FMT, enc_pkt, socket.inet_aton(router.get_ip_addr()), router.get_port(), router.get_pub_key(), sid, sym_key)

        return route

    def _create_route(self):
        shuffled_routers = self.server.routers.shuffle_routers()
        self._send(self._enc_route(shuffled_routers[:min(len(shuffled_routers), MAX_PATH_LENGTH)]))

    def _create_route_optimized(self):
        routes = self.server.conn_graph.get_paths(self.client_address[0])
        route_data = ""
        for route in routes:
            route_data += self._enc_route(route)
        self._send(route_data)

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
            elif request_type == MSG_TYPES.GET_ROUTE_OPTIMIZED:
                self._output("Creating optimized routes")
                self._create_route_optimized()
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
