# from pathing_server_interface import PathingServerInterface, PathingFailed
import argparse
import logging
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import sys
from TorPathingServer import TORPathingServer, PathingFailed, TestTORPathingServer
from TorRouter import TorRouterInterface, TestTorRouterInterface, CircuitFailed
from Crypt import Crypt

root = logging.getLogger()
root.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int, help="Port to bind Tor proxy to")
    parser.add_argument("pip", help="IP address of Tor pathfinding server")
    parser.add_argument("pport", type=int, help="IP address of Tor pathfinding server")
    parser.add_argument("--dbpath", help="")
    parser.add_argument("--testti", help="Include to use test tor_interface", action='store_true')
    args = parser.parse_args()
    return args.port, args.pip, args.pport, args.testti


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
            # print "*" * 20, url, self.raw_requestline
            # print "getting host"
            # print self.headers.dict
            # print self.raw_requestline
            # url = self.headers.dict['host']
            # print url
            # headers = str(self.headers)
            # path = '/'.join(str(self.path).split("/")[3:])  # todo: do this better
            # request = "%s /%s %s\r\n%s\r\n" % (method, path, self.protocol_version, headers)
            logging.info("Sending request")
            resp = tor_interface.make_request(url, self.raw_requestline + str(self.headers) + "\r\n")
            logging.info("Returning request...")
            self.wfile.write(resp)
            logging.info("Served client")
        except KeyError:
            logging.error("Bad request")
            self.send_error(400)

    def do_CONNECT(self):
        logging.info("Handling CONNECT")
        self.forward_request()

    def do_DELETE(self):
        logging.info("Handling DELETE")
        self.forward_request()

    def do_GET(self):
        logging.info("Handling GET")
        self.forward_request()

    def do_HEAD(self):
        logging.info("Handling HEAD")
        self.forward_request()

    def do_OPTIONS(self):
        logging.info("Handling OPTIONS")
        self.forward_request()

    def do_PATCH(self):
        logging.info("Handling PATCH")
        self.forward_request()

    def do_POST(self):
        logging.info("Handling POST")
        self.forward_request()

    def do_PUT(self):
        logging.info("Handling PUT")
        self.forward_request()


class TorClient(object):

    def __init__(self, port, p_ip, p_port, test):
        self.test = test
        if test:
            self.path_server = TestTORPathingServer(p_ip, p_port)
        else:
            self.path_server = TORPathingServer(p_ip, p_port)
        self.has_route = False
        logging.info("Initializing TorProxy server")
        self.tp = HTTPServer(('localhost', port), TorProxy)

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
                # print route
                tr3 = TestTorRouterInterface(route[2], is_exit=True, router_key=rk3, server_pubkey=spk)
                tr2 = TestTorRouterInterface(route[1], tr3, router_key=rk2, server_pubkey=spk)
                tor_interface = TestTorRouterInterface(route[0], tr2, is_entry=True, router_key=rk1, server_pubkey=spk)
            else:
                tr3 = TorRouterInterface(route[2])
                tr2 = TorRouterInterface(route[1], tr3)
                tor_interface = TorRouterInterface(route[0], tr2, True)
            tor_interface.establish_circuit()
            self.has_route = True

    def run_client(self):
        global tor_interface
        while True:
            try:
                logging.info("Establishing new path")
                self.establish_path()
                logging.info("Starting server")
                self.tp.serve_forever()
            except PathingFailed:
                logging.error("Pathing failed: try again later")
                return
            except CircuitFailed:
                logging.error("Circuit failed!")
                try:
                    tor_interface.close_circuit()
                except CircuitFailed:
                    logging.error("Closing circuit failed! Network may be corrupted")
                    return
            except:
                logging.info("Closing circuit...")
                try:
                    tor_interface.close_circuit()
                except CircuitFailed:
                    logging.error("Closing circuit failed! Network may be corrupted")
                    return
                logging.info("Exiting")
                return


def main():
    port, p_ip, p_port, testti = parse_args()

    tc = TorClient(port, p_ip, p_port, testti)
    tc.run_client()


if __name__ == "__main__":
    main()
