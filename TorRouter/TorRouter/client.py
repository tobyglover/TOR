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
address = tps.get_route()[0]

logging.info("Creating TorRouterInterface")
tr = TorRouterInterface(address, entry=True)

logging.info("Establishing circuit")
tr.establish_circuit()
