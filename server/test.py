from client_interface import TORPathingServer
from Crypto.PublicKey import RSA
import sys

def test():
    key = RSA.generate(2048).publickey()
    server = TORPathingServer("localhost", int(sys.argv[1]))
    server.register(2100, key)
    route = server.get_route()
    
    print route[0][2] == key
    print route
    server.unregister()
    print server.get_route()

if __name__ == '__main__':
    test()
