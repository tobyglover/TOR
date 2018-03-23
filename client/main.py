from pathing_server_interface import PathingServerInterface, PathingFailed
from tor_interface import TorInterface, TorRelayMiddle, TorRelayExit, TestTorInterface
import argparse
import logging
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
# from http.server import HTTPServer
import sys

root = logging.getLogger()
root.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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

    def do_GET(self):
        try:
            url = self.headers.dict['host']
            # print self.headers.dict
            self.headers.dict.pop('proxy-connection')
            headers = str(self.headers).replace("Proxy-", "")
            # print headers
            # print self.headers.dict
            # print str(self.headers)
            # print self.client_address
            # print self.raw_requestline
            path = '/'.join(str(self.path).split("/")[3:])
            request = "GET /%s %s\r\n%s\r\n" % (path, self.protocol_version, headers)
            logging.info("Getting request")
            resp = tor_interface.do_get(url, request)
            logging.info("Returning request")
            self.wfile.write(resp)
        except KeyError:
            logging.error("Bad request")
            self.send_error(400)

        # self.send_response(200)
        # self.end_headers()
        # self.wfile.write(b'Hello, world!')
        # print "*** COMMAND:"
        # print self.command
        # print "*** PROTOCOL_VERSION"
        # print self.protocol_version
        # print "*** PATH"
        # print self.path
        # # print "*** RESPONSES"
        # # print self.responses
        # print "*** CLIENT ADDRESS:"
        # print self.client_address
        # print "*** HEADERS:"
        # print self.headers
        # print "*** HOST:"
        # print self.headers.dict['host']
        # print "*** REQUEST ***"
        # print "GET %s %s\n%s" % (self.path, self.protocol_version, str(self.headers))


class TorClient(object):

    def __init__(self, port, p_ip, p_port, testti):
        global tor_interface
        self.path_server = PathingServerInterface(p_ip, p_port)
        tor_interface = TestTorInterface() if testti else TorInterface()
        self.has_route = False
        logging.info("Initializing TorProxy server")
        self.tp = HTTPServer(('localhost', port), TorProxy)

    def establish_path(self):
        # TODO: stale path
        if not self.has_route:
            route = self.path_server.get_route()
            tr3 = TorRelayExit(route[2])
            tr2 = TorRelayMiddle(route[1], tr3)
            tr1 = TorRelayMiddle(route[0], tr2)
            tor_interface.establish_path(tr1)
            self.has_route = True

    def run_client(self):
        while True:
            try:
                logging.info("Establishing path")
                self.establish_path()
                logging.info("Starting server")
                self.tp.serve_forever()
            except PathingFailed:
                print "Pathing failed: try again later"
                return


def main():
    port, p_ip, p_port, testti = parse_args()

    tc = TorClient(port, p_ip, p_port, testti)
    tc.run_client()


if __name__ == "__main__":
    main()
