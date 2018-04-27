import uuid
from random import shuffle
from Crypto.PublicKey import RSA

class Graph(object):
    def __init__(self):
        self._nodes = {}

    def add_router(self, router):
        region = router.get_region()
        node = self._nodes.get(region, None)

        if node is None:
            node = Node(region)
            self._nodes[region] = node

        node.add_router(router)

    def get_next_test(self, from_router):
        return None
        for k in self.tor_routers.keys():
            if k != from_router_id and "daemon_port" in self.server.tor_routers[k]:
                return k
        return None


class Node(object):
    def __init__(self, region):
        self._region = region
        self._routers = []
        self._edges = {}

    def add_router(self, router):
        self._routers.append(router)

class Edge(object):
    def __init__(self, region1, region2, latency=0):
        self._num_tests = 0
        self._sum_latency = latency
        if latency > 0:
            self._num_tests = 1

    def add_test(self, latency):
        self._sum_latency += latency
        self._num_tests += 1

    def get_average(self):
        return self._sum_latency / self._num_tests

class Router(object):
    def __init__(self, ip_addr, port, pub_key):
        self.id = uuid.uuid4().bytes
        self.ip_addr = ip_addr
        self.port = port
        self.pub_key = pub_key
        self.daemon_port = None
        self.region = None

    def __str__(self):
        return "Router %s:%d" % (self.get_ip_addr(), self.get_port())

    def get_id(self):
        return self.id

    def get_ip_addr(self):
        return self.ip_addr

    def get_port(self):
        return self.port

    def get_daemon_port(self):
        return self.daemon_port

    def set_daemon_port(self, port):
        self.daemon_port = port

    def get_pub_key(self, parse=False):
        if parse:
            return RSA.import_key(self.pub_key)
        return self.pub_key

    def get_region(self):
        if self.region is None:
            #TODO
            self.region = "U32"
        return self.region

class Routers(object):
    def __init__(self):
        self._routers = {}

    def __str__(self):
        return self._routers.__str__()

    def add_router(self, router):
        self._routers[router.get_id()] = router

    def get_router(self, router_id):
        return self._routers.get(router_id, None)

    def pop_router(self, router_id):
        return self._routers.pop(router_id, None)

    def shuffle_routers(self):
        routers = self._routers.values()
        shuffle(routers)
        return routers


def get_region_for_ip(ip):
    pass
