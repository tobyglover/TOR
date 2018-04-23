import argparse
import logging
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
import sys
from TorPathingServer import TORPathingServer, PathingFailed, TestTORPathingServer
from TorRouter import TorRouterInterface, TestTorRouterInterface, CircuitFailed
from Crypt import Crypt
from Crypto.PublicKey import RSA
import thread


client_logger = logging.getLogger("Client")
ch = logging.StreamHandler(sys.stdout)
client_logger.setLevel(logging.DEBUG)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
client_logger.addHandler(ch)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int, help="Port to bind Tor proxy to")
    parser.add_argument("pip", help="IP address of Tor pathfinding server")
    parser.add_argument("pport", type=int, help="IP address of Tor pathfinding server")
    parser.add_argument("pubkey", help="Path to the PathingServer public key")
    parser.add_argument("--testti", help="Include to use test tor_interface", action='store_true')
    args = parser.parse_args()
    return args.port, args.pip, args.pport, args.pubkey, args.testti


tor_interface = None


class TorProxy(BaseHTTPRequestHandler):

    def clean_url(self, url):
        if "://" in url:
            return url.split('/')[2]
        return url.split('/')[0]

    def forward_request(self):
        # return
        try:
            _, url, _ = self.raw_requestline.split(' ')
            url = self.clean_url(url)
            # print "*" * 20, url, self.raw_requestline
            # print "getting host"
            # print self.headers.dict
            # print self.raw_requestline
            # url = self.headers.dict['host']
            # print url
            # headers = str(self.headers)
            # path = '/'.join(str(self.path).split("/")[3:])  # todo: do this better
            # request = "%s /%s %s\r\n%s\r\n" % (method, path, self.protocol_version, headers)
            client_logger.info("Sending request")
            resp = tor_interface.make_request(url, self.raw_requestline + str(self.headers) + "\r\n")
            client_logger.info("Returning request...")
            self.wfile.write(resp)
            client_logger.info("Served client")
        except KeyError:
            client_logger.error("Bad request")
            self.send_error(400)

    def do_CONNECT(self):
        client_logger.info("Handling CONNECT")
        thread.start_new_thread(self.forward_request, ())
        # self.forward_request()

    def do_DELETE(self):
        client_logger.info("Handling DELETE")
        thread.start_new_thread(self.forward_request, ())
        # self.forward_request()

    def do_GET(self):
        # self.send_response(200)
        # self.end_headers()
        # self.wfile.write("hello world!\n" * 500)
        client_logger.info("Handling GET")
        # thread.start_new_thread(self.forward_request, ())
        self.forward_request()

    def do_HEAD(self):
        client_logger.info("Handling HEAD")
        # thread.start_new_thread(self.forward_request, ())
        self.forward_request()

    def do_OPTIONS(self):
        client_logger.info("Handling OPTIONS")
        # thread.start_new_thread(self.forward_request, ())
        self.forward_request()

    def do_PATCH(self):
        client_logger.info("Handling PATCH")
        # thread.start_new_thread(self.forward_request, ())
        self.forward_request()

    def do_POST(self):
        client_logger.info("Handling POST")
        # thread.start_new_thread(self.forward_request, ())
        self.forward_request()

    def do_PUT(self):
        client_logger.info("Handling PUT")
        # thread.start_new_thread(self.forward_request, ())
        self.forward_request()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    pass


class TorClient(object):

    def __init__(self, port, p_ip, p_port, pubkey, test):
        self.test = test
        if test:
            self.path_server = TestTORPathingServer(p_ip, p_port)
        else:
            self.path_server = TORPathingServer(p_ip, p_port, pubkey)
        self.has_route = False
        client_logger.info("Initializing TorProxy server")
        self.tp = ThreadedHTTPServer(('localhost', port), TorProxy)
        # self.tp = HTTPServer(('localhost', port), TorProxy)

    def establish_path(self):
        global tor_interface

        # TODO: stale path
        if not self.has_route:
            if self.test:
                rk1 = Crypt().generate_key()
                rk2 = Crypt().generate_key()
                rk3 = Crypt().generate_key()
                spk = self.path_server.private_key.publickey()
                self.path_server.register(1, rk1.publickey())
                self.path_server.register(2, rk2.publickey())
                self.path_server.register(3, rk3.publickey())
            route = self.path_server.get_route()
            if self.test:
                # print "test"
                # print route
                tr3 = TestTorRouterInterface(route[2], is_exit=True, router_key=rk3, server_pubkey=spk)
                tr2 = TestTorRouterInterface(route[1], tr3, router_key=rk2, server_pubkey=spk)
                tor_interface = TestTorRouterInterface(route[0], tr2, is_entry=True, router_key=rk1, server_pubkey=spk)
                # print "made"
            else:
                client_logger.debug("Route %s:%d -> %s:%d -> %s:%d" % (route[0][1], route[0][2],
                                                                       route[1][1], route[1][2],
                                                                       route[2][1], route[2][2]))
                tr3 = TorRouterInterface(route[2])
                tr2 = TorRouterInterface(route[1], tr3)
                tor_interface = TorRouterInterface(route[0], tr2, True)
            tor_interface.establish_circuit()
            self.has_route = True

    def run_client(self):
        global tor_interface
        while True:
            try:
                client_logger.info("Establishing new path")
                self.establish_path()
                client_logger.info("Starting server")
                self.tp.serve_forever()
            except PathingFailed:
                client_logger.error("Pathing failed: try again later")
                return
            except CircuitFailed:
                client_logger.error("Circuit failed!")
                try:
                    tor_interface.close_circuit()
                except CircuitFailed:
                    client_logger.error("Closing circuit failed! Network may be corrupted")
                    return
            except:
                client_logger.error("Received exception")
                e = sys.exc_info()
                if tor_interface:
                    client_logger.info("Closing circuit...")
                    try:
                        tor_interface.close_circuit()
                    except CircuitFailed:
                        e = sys.exc_info()
                        client_logger.error("Closing circuit failed! Network may be corrupted")
                        raise e[0], e[1], e[2]
                client_logger.info("Exiting")
                raise e[0], e[1], e[2]


def main():
    port, p_ip, p_port, pubkeyp, testti = parse_args()

    with open(pubkeyp, "r") as f:
        pubkey = RSA.importKey(f.read())

    tc = TorClient(port, p_ip, p_port, pubkey, testti)
    tc.run_client()


if __name__ == "__main__":
    main()
