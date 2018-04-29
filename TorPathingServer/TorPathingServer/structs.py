import uuid
import utm
from math import sqrt
import urllib2
import json
from random import shuffle, choice, randint
from Crypto.PublicKey import RSA

IP_STACK_ACCESS_KEY = "702000af0f3cb5843bf102c88974b4e9"

class Graph(object):
    def __init__(self):
        self._nodes = {}

    def __str__(self):
        string = ""
        for region in self._nodes:
            string += str(self._nodes[region])
        return string

    def _get_node_for_region(self, region):
        return self._nodes.get(region, None)

    def _get_node_for_router(self, router):
        region = router.get_region()
        return self._get_node_for_region(region)

    def add_test_results(self, from_region, to_region, latency):
        from_node = self._get_node_for_region(from_region)
        to_node = self._get_node_for_region(to_region)

        if not from_node is None and not to_node is None:
            edge = Edge(set([from_region, to_region]), latency=latency)
            if from_node.has_edge(edge):
                from_node.update_edge(edge)
            else:
                to_node.add_edge(edge)
                from_node.add_edge(edge)

    def get_next_test(self, from_router):
        from_node = self._get_node_for_router(from_router)
        if from_node is None:
            return None

        available_regions = set(self._nodes.keys())
        available_regions.remove(from_node.get_region())

        if len(available_regions) == 0:
            return None

        for _ in range(3):
            to_region = from_node.get_needed_test_region(available_regions)
            to_node = self._get_node_for_region(to_region)
            to_router = to_node.get_test_router()
            if not to_router is None:
                return to_router

        return None

    def add_router(self, router):
        node = self._get_node_for_router(router)
        if node is None:
            region = router.get_region()
            node = Node(region)
            self._nodes[region] = node

        node.add_router(router)

    def remove_node(self, node):
        self._nodes.pop(node.get_region())
        for region in self._nodes:
            self._nodes[region].remove_edge(node.get_region())

    def remove_router(self, router):
        node = self._get_node_for_router(router)
        if not node is None:
            node.remove_router(router)
            if node.is_empty():
                self.remove_node(node)

    def _get_latency_between_nodes(self, start_node, end_node, randomness=0):
        if start_node == end_node:
            return -1
        edge = start_node.get_edge(end_node.get_region())
        if edge is None:
            return -1

        latency = edge.get_average_latency()
        return latency + randint(max(-randomness, -int(latency)), randomness)

    def _get_path(self, start_node, end_node, randomness):
        min_latency = 0
        min_node = None
        for middle_region in self._nodes:
            middle_node = self._nodes[middle_region]
            start_latency = self._get_latency_between_nodes(start_node, middle_node, randomness)
            end_latency = self._get_latency_between_nodes(middle_node, end_node, randomness)
            if start_latency < 0 or end_latency < 0:
                continue

            total_latency = start_latency + end_latency
            if min_node is None or total_latency < min_latency:
                min_node = middle_node
                min_latency = total_latency

        return [start_node.get_random_router(), min_node.get_random_router(), end_node.get_random_router()]

    def get_paths(self, client_ip, randomness=5):
        start_node = self.get_closest_node_in_graph(get_region_for_ip(client_ip))
        end_regions = get_random_regions_for_continents()

        paths = []
        for end_region in end_regions:
            end_node = self.get_closest_node_in_graph(end_region)
            paths.append(self._get_path(start_node, end_node, randomness))

        return paths

    def get_closest_node_in_graph(self, to_region):
        if to_region in self._nodes:
            return to_region
        else:
            regions = self._nodes.keys()
            min_dist = 0
            closest_region = None

            for region in regions:
                dist = calc_distance_between_regions(to_region, region)
                if closest_region is None or min_dist > dist:
                    closest_region = region
                    min_dist = dist

            return self._get_node_for_region(closest_region)


class Node(object):
    def __init__(self, region):
        self._region = region
        self._routers = {}
        self._edges = {}

    def __str__(self):
        string = "Region %s: %d routers, %d edges\n" % (self._region, len(self._routers), len(self._edges))
        for to_region in self._edges:
            edge = self._edges[to_region]
            string += "\t--->> %s: Latency %f ms (%d tests)\n" % (to_region, edge.get_average_latency(), edge.get_num_tests())

        return string

    def __eq__(self, other):
        return self.get_region() == other.get_region()

    def _get_connected_regions(self):
        connected_regions = set()
        for edge in self._edges.values():
            connected_regions.add(edge.get_other_region(self._region))

        return connected_regions

    def get_region(self):
        return self._region

    def add_router(self, router):
        self._routers[router.get_id()] = router

    def remove_router(self, router):
        self._routers.pop(router.get_id(), None)

    def get_random_router(self):
        return choice(self._routers.values())

    def has_edge(self, edge):
        to_region = edge.get_other_region(self.get_region())
        return to_region in self._edges

    def get_edge(self, to_region):
        return self._edges.get(to_region, None)

    def add_edge(self, edge):
        to_region = edge.get_other_region(self.get_region())
        self._edges[to_region] = edge

    def update_edge(self, edge):
        to_region = edge.get_other_region(self.get_region())
        current_edge = self._edges.get(to_region, None)
        current_edge.add(edge)

    def remove_edge(self, region):
        self._edges.pop(region, None)

    def get_needed_test_region(self, available_regions):
        connected_regions = self._get_connected_regions()
        needed_regions = available_regions - connected_regions
        if len(needed_regions) > 0:
            return needed_regions.pop()
        else:
            return available_regions.pop()

    def get_test_router(self):
        if len(self._routers) == 0:
            return None

        for _ in range(3):
            router = choice(self._routers.values())
            if not router.get_daemon_port() is None:
                return router

        return None

    def is_empty(self):
        return len(self._routers) == 0

class Edge(object):
    def __init__(self, regions, latency=0):
        self._regions = regions
        self._num_tests = 0
        self._sum_latency = latency
        if latency > 0:
            self._num_tests = 1

    def get_other_region(self, region):
        return (self._regions - set([region])).pop()

    def get_regions(self):
        return self._regions

    def get_sum_latency(self):
        return self._sum_latency

    def get_num_tests(self):
        return self._num_tests

    def add(self, edge):
        if self._regions == edge.get_regions():
            self._sum_latency += edge.get_num_tests()
            self._num_tests += edge.get_num_tests()

    def get_average_latency(self):
        return self._sum_latency / self._num_tests

class Routers(object):
    def __init__(self):
        self._routers = {}

    def __str__(self):
        return str(self._routers)

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

class Router(object):
    def __init__(self, ip_addr, port, pub_key):
        self.id = uuid.uuid4().bytes
        self.ip_addr = ip_addr
        self.port = port
        self.pub_key = pub_key
        self.daemon_port = None
        self.region = None

    def __str__(self):
        daemon_port = self.daemon_port
        if daemon_port is None:
            daemon_port = "None"
        return "Router %s:%d, daemon_port:%d, region:%s" % (self.get_ip_addr(), self.get_port(), daemon_port, self.get_region())

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
            self.region = get_region_for_ip(self.ip_addr)
        return self.region

#returns a list of three random regions from the americas, europe, and asia
def get_random_regions_for_continents():
    americas = (("P", "U"), (9, 20))
    europe = (("S", "V"), (29, 37))
    asia = (("R", "W"), (38, 55))

    continents = [americas, europe, asia]
    regions = []
    for continent in continents:
        letter = chr(randint(ord(continent[0][0]), ord(continent[0][1])))
        number = randint(continent[1][0], continent[1][1])
        regions.append((letter, number))

    return regions

def calc_distance_between_regions(region1, region2):
    return sqrt((ord(region1[0]) - ord(region2[0])) ** 2 + (region1[1] - region2[1]) ** 2)

def get_region_for_ip(ip):
    url = "http://api.ipstack.com/%s?access_key=%s&fields=latitude,longitude" % (ip, IP_STACK_ACCESS_KEY)
    c = urllib2.urlopen(url).read()
    coords = json.loads(c)
    try:
        utm_pos = utm.from_latlon(coords["latitude"], coords["longitude"])
        letter = utm_pos[3]
        number = utm_pos[2]
    except:
        # pick a random region. Mainly for testing on localhost, this (probably) won't happen in production
        letter = chr(randint(65, 90))
        number = randint(1, 60)

    return (letter, number)
