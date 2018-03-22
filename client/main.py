from pathing_server_interface import PathingServerInterface, PathingFailed
from tor_interface import TorInterface, TorRelay
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int, help="Port to bind Tor proxy to")
    parser.add_argument("pip", help="IP address of Tor pathfinding server")
    parser.add_argument("pport", type=int, help="IP address of Tor pathfinding server")
    args = parser.parse_args()
    return args.port, args.pip, args.pport


tor_interface = None


class TorProxy(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            url = self.headers.dict['host']
            request = "GET %s %s\n%s" % (self.path, self.protocol_version, str(self.headers))
            resp = tor_interface.do_get(url, request)
            self.wfile.write(resp)
        except KeyError:
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

    def __init__(self, port, p_ip, p_port):
        global tor_interface
        self.path_server = PathingServerInterface(p_ip, p_port)
        tor_interface = TorInterface()
        self.has_route = False
        self.tp = HTTPServer(('localhost', port), TorProxy)

    def establish_path(self):
        # TODO: stale path
        if not self.has_route:
            route = self.path_server.get_route()
            tr1 = TorRelay(route[0])
            tr2 = TorRelay(route[0])
            tr3 = TorRelay(route[0])
            self.has_route = True
            tor_interface.establish_path(tr1, tr2, tr3)

    def run_client(self):
        while True:
            try:
                self.establish_path()
                self.tp.serve_forever()
            except PathingFailed:
                print "Pathing failed: try again later"
                return


def main():
    port, p_ip, p_port = parse_args()
    tc = TorClient(port, p_ip, p_port)
    tc.run_client()


if __name__ == "__main__":
    main()
