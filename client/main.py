from pathing_server_interface import PathingServerInterface
from tor_interface import TorInterface
import argparse
import cmd


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="IP address of Tor pathfinding server")
    parser.add_argument("--port", help="IP address of Tor pathfinding server")
    args = parse_args()
    return args["ip"], args["port"]


class ClientInterface(cmd.Cmd):
    intro = "Welcome to the Tor network, type help or ? to list commands.\n"
    prompt = "> "

    def __init__(self, ip, port):
        super(ClientInterface, self).__init__()
        self.path_server = PathingServerInterface(ip, port)
        self.tor_interface = TorInterface()

    def do_connect(self, args):
        route = self.path_server.get_route()
        try:




def main():
    ip, port = parse_args()
    ClientInterface(ip, port).cmdloop()


if __name__ == "__main__":
    main()