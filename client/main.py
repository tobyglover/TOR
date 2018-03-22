from pathing_server_interface import PathingServerInterface, PathingFailed
from tor_interface import TorInterface, TorRelay
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", help="Port to bind Tor proxy to")
    parser.add_argument("--pip", help="IP address of Tor pathfinding server")
    parser.add_argument("--pport", help="IP address of Tor pathfinding server")
    args = parse_args()
    return args.port, args.pip, args.pport




class TorProxy(BaseHTTPRequestHandler):
    intro = "Welcome to the Tor network, type help or ? to list commands.\n"
    prompt = "> "

    def __init__(self, ip, port):
        super(TorProxy, self).__init__()
        self.path_server = PathingServerInterface(ip, port)
        self.tor_interface = TorInterface()
        self.has_route = False

    def establish_path(self):
        # TODO: stale path
        if not self.has_route:
            route = self.path_server.get_route()
            self.tr1 = TorRelay(route[0])
            self.tr2 = TorRelay(route[0])
            self.tr3 = TorRelay(route[0])
            self.has_route = True
            self.tor_interface.establish_path(self.tr1, self.tr2, self.tr3)

    def do_connect(self, args):
        try:
            self.establish_path()

        except PathingFailed:
            print "Pathing failed: try again later"


def main():
    port, p_ip, p_port = parse_args()
    tp = HTTPServer(('localhost', port), TorProxy)
    tp = HTTPServer(('localhost', port))
    TorProxy(p_ip, p_port).serve_forever()


if __name__ == "__main__":
    main()