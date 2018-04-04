# from pathing_server_interface import PathingServerInterface, PathingFailed
import argparse
import logging
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import sys
from TorPathingServer import TORPathingServer, PathingFailed
from TorRouter import TorRouterInterface

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
    parser.add_argument("--testti", help="Include to use test tor_interface", action='store_true')
    args = parser.parse_args()
    return args.port, args.pip, args.pport, args.testti


tor_interface = None


class TorProxy(BaseHTTPRequestHandler):

    def forward_request(self, method):
        try:
            url = self.headers.dict['host']
            # self.headers.dict.pop('proxy-connection')
            headers = str(self.headers).replace("Proxy-", "")
            path = '/'.join(str(self.path).split("/")[3:])
            request = "%s /%s %s\r\n%s\r\n" % (method, path, self.protocol_version, headers)
            logging.info("Sending request")
            resp = tor_interface.make_request(url, request)
            logging.info("Returning request...")
            self.wfile.write(resp)
            logging.info("Served client")
        except KeyError:
            logging.error("Bad request")
            self.send_error(400)

    def do_CONNECT(self):
        logging.info("Handling CONNECT")
        self.forward_request("CONNECT")

    def do_DELETE(self):
        logging.info("Handling DELETE")
        self.forward_request("DELETE")

    def do_GET(self):
        logging.info("Handling GET")
        self.forward_request("GET")

    def do_HEAD(self):
        logging.info("Handling HEAD")
        self.forward_request("HEAD")

    def do_OPTIONS(self):
        logging.info("Handling OPTIONS")
        self.forward_request("OPTIONS")

    def do_PATCH(self):
        logging.info("Handling PATCH")
        self.forward_request("PATCH")

    def do_POST(self):
        logging.info("Handling POST")
        self.forward_request("POST")

    def do_PUT(self):
        logging.info("Handling PUT")
        self.forward_request("PUT")


class TorClient(object):

    def __init__(self, port, p_ip, p_port):
        global tor_interface
        self.path_server = TORPathingServer(p_ip, p_port)
        self.has_route = False
        logging.info("Initializing TorProxy server")
        self.tp = HTTPServer(('localhost', port), TorProxy)

    def establish_path(self):
        global tor_interface

        # TODO: stale path
        if not self.has_route:
            route = self.path_server.get_route()
            tr3 = TorRouterInterface(route[2])
            tr2 = TorRouterInterface(route[1], tr3)
            tor_interface = TorRouterInterface(route[0], tr2, True)
            tor_interface.establish_circuit()
            self.has_route = True

    def run_client(self):
        global tor_interface
        while True:
            try:
                logging.info("Establishing path")
                self.establish_path()
                logging.info("Starting server")
                self.tp.serve_forever()
            except PathingFailed:
                print "Pathing failed: try again later"
                return
            except:
                logging.info("Closing circuit...")
                tor_interface.close_circuit()
                logging.info("Exiting")
                break


def main():
    port, p_ip, p_port, testti = parse_args()

    tc = TorClient(port, p_ip, p_port)
    tc.run_client()


if __name__ == "__main__":
    main()
