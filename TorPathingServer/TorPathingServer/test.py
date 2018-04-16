from client_interface import TORPathingServer
from Crypto.PublicKey import RSA
import time
import sys

def getServer():
    return TORPathingServer(sys.argv[1], int(sys.argv[2]))

def test():
    router_config = [(2100, RSA.generate(2048)), (2101, RSA.generate(2048)), (2102, RSA.generate(2048))]
    routers = []

    for (port, key) in router_config:
        router = getServer()
        router.register(port, key.publickey())
        routers.append(router)

    route = getServer().get_route()
    count_correct = 0

    for (_, _, port, key, _, _) in route:
        for (router_port, router_key) in router_config:
            if port == router_port and key == router_key.publickey():
                count_correct += 1

    assert count_correct == len(router_config)
    routers.pop()
    for router in routers:
        router.unregister()

    assert len(getServer().get_route()) == 0

    print "Test Passed"


if __name__ == '__main__':
    test()
