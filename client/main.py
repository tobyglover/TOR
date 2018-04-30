import argparse
import logging
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
import sys
from TorPathingServer import TORPathingServer, PathingFailed
from TorRouter import TorRouterInterface, TestTorRouterInterface, CircuitFailed
from Crypt import Crypt
from Crypto.PublicKey import RSA
import thread

# logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

client_logger = logging.getLogger("Client")
client_logger.setLevel(logging.INFO)
# if not client_logger.handlers:
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
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
        try:
            _, url, _ = self.raw_requestline.split(' ')
            url = self.clean_url(url)
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
        self.forward_request()

    def do_DELETE(self):
        client_logger.info("Handling DELETE")
        self.forward_request()

    def do_GET(self):
        client_logger.info("Handling GET")
        self.forward_request()

    def do_HEAD(self):
        client_logger.info("Handling HEAD")
        self.forward_request()

    def do_OPTIONS(self):
        client_logger.info("Handling OPTIONS")
        self.forward_request()

    def do_PATCH(self):
        client_logger.info("Handling PATCH")
        self.forward_request()

    def do_POST(self):
        client_logger.info("Handling POST")
        self.forward_request()

    def do_PUT(self):
        client_logger.info("Handling PUT")
        self.forward_request()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    pass


class TorClient(object):

    def __init__(self, port, p_ip, p_port, pubkey):
        self.path_server = TORPathingServer(p_ip, p_port, pubkey)
        self.has_route = False
        client_logger.info("Initializing TorProxy server")
        self.tp = ThreadedHTTPServer(('localhost', port), TorProxy)

    def establish_path(self):
        global tor_interface

        # TODO: stale path
        if not self.has_route:
            route = self.path_server.get_route()
            client_logger.debug("Route %s:%d -> %s:%d -> %s:%d" %
                                (route[0][1], route[0][2],
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
            except KeyboardInterrupt:
                client_logger.warning("Received keyboard interrupt")
                if tor_interface:
                    client_logger.info("Closing circuit...")
                    try:
                        tor_interface.close_circuit()
                    except CircuitFailed:
                        e = sys.exc_info()
                        client_logger.error("Closing circuit failed! Network may be corrupted")
                        raise e[0], e[1], e[2]
                client_logger.info("Exiting cleanly")
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

    tc = TorClient(port, p_ip, p_port, pubkey)
    tc.run_client()


if __name__ == "__main__":
    main()
