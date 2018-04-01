import socket
import sys
from TorRouter import TorRouterInterface
from TorPathingServer import TORPathingServer
import argparse
import logging

root = logging.getLogger()
root.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)

parser = argparse.ArgumentParser()
parser.add_argument("--pip", default="localhost")
parser.add_argument("--pport", type=int, default=8000)
args = parser.parse_args()
pip, pport = args.pip, args.pport

logging.info("Getting path")
tps = TORPathingServer(pip, pport)
# address = tps.get_route()[0]
#
# logging.info("Creating TorRouterInterface")
# tr = TorRouterInterface(address, entry=True)
#
# logging.info("Establishing circuit")
# tr.establish_circuit()
#
# logging.info("Making request")
# print tr.make_request("www.google.com", "GET / HTTP/1.1\nHost: www.google.com\n\n")
#
# print
# print
# logging.info("RECEIVED PAYLOAD!!!")
# print
# print

logging.info("Getting path")
addresses = tps.get_route()

logging.info("Creating TorRouterInterfaces")
trexit  = TorRouterInterface(addresses[0])
trentry = TorRouterInterface(addresses[1], next_router=trexit, entry=True)

trentry.establish_circuit()

logging.info("Making request")
print trentry.make_request("www.google.com", "GET / HTTP/1.1\nHost: www.google.com\n\n")
