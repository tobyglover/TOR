from Crypt import Crypt
from Crypto.PublicKey import RSA
import logging
import socket


class TorRouterInterface(object):

    CT_BLOCK_SIZE = 256
    HEADER_SIZE = 2 * CT_BLOCK_SIZE

    def __init__(self, (ip, port, tor_pubkey), next_router=None, entry=False):
        client_key = Crypt().generate_key()
        self.client_pubkey = client_key.publickey()
        self.tor_pubkey = tor_pubkey
        self.crypt = Crypt(public_key=tor_pubkey,
                           private_key=client_key)
        self.prev_pubkey_der = None
        self.next_router = next_router
        self.entry = entry
        self.ip = ip
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logging.info("Initialized TorRouterInterface")

    def pull(self, length):
        message = ''
        while len(message) < length:
            message += self.s.recv(length - len(message))
        return message

    def establish_circuit(self, prev_pubkey=None):
        logging.info("Establishing circuit")
        if self.entry:
            self.prev_pubkey_der = self.client_pubkey.exportKey(format='DER')
        else:
            self.prev_pubkey_der = prev_pubkey.exportKey(format='DER')

        pubkey = self.client_pubkey.exportKey(format='DER')

        packet = self.prev_pubkey_der
        if self.next_router:
            packet += self.next_router.tor_pubkey.exportKey(format='DER')
            packet += self.next_router.establish_circuit(prev_pubkey=self.tor_pubkey)
            packet = self.crypt.sign_and_encrypt(packet)
            header = "%d:%s:%d" % (len(packet) / self.CT_BLOCK_SIZE,
                                   self.next_router.ip, self.next_router.port)
            header = self.crypt.sign_and_encrypt(header)
        else:
            packet = self.crypt.sign_and_encrypt(packet)
            header = "%d:EXIT:" % (len(packet) / self.CT_BLOCK_SIZE)
            header = self.crypt.sign_and_encrypt(header)

        logging.debug("ppd: %d, h: %d, p: %d" % (len(self.prev_pubkey_der), len(header), len(packet)))
        packet = pubkey + header + packet

        if self.entry:
            self.s.connect((self.ip, self.port))
            logging.info("Entry TRI sending packet of len %d" % len(packet))
            self.s.sendall(packet)
        else:
            logging.info("Later TRI returning packet of len %d" % len(packet))
            return packet

    def peel_onion(self, onion):
        if self.next_router:
            onion = self.crypt.decrypt_and_auth(onion)
            return self.next_router.peel_onion(onion)
        return self.crypt.decrypt_and_auth(onion)

    def make_request(self, url, request):
        url_port = url.split(":")
        ip = socket.gethostbyname(url_port[0])
        port = int(url_port[1]) if len(url_port) == 2 else 80

        logging.info("Requesting %s:%d" % (ip, port))

        if self.next_router:
            packet = self.next_router.make_request(url, request)
            packet = self.crypt.sign_and_encrypt(packet)
            header = "%d:" % (len(packet) / self.CT_BLOCK_SIZE)
            packet = self.crypt.sign_and_encrypt(header) + packet
        else:
            packet = self.crypt.sign_and_encrypt(request)
            header = "%d:%s:%d" % (len(packet) / self.CT_BLOCK_SIZE, ip, port)
            packet = self.crypt.sign_and_encrypt(header) + packet

        if self.entry:
            logging.info("Sending packet")
            self.s.sendall(packet)
        else:
            return packet

        logging.info("Waiting for response...")
        header = self.pull(self.HEADER_SIZE)
        num_chunks = int(self.crypt.decrypt_and_auth(header))

        onion = self.pull(num_chunks * self.CT_BLOCK_SIZE)
        logging.info("Received response")
        return self.peel_onion(onion)

    def close_circuit(self):
        if self.next_router:
            packet = self.next_router.close_circuit()
            packet = self.crypt.sign_and_encrypt(packet)
            header = "%d:CLOSE" % (len(packet) / self.CT_BLOCK_SIZE)
            packet = self.crypt.sign_and_encrypt(header) + packet
        else:
            packet = "0:CLOSE:"
            packet = self.crypt.sign_and_encrypt(packet)

        if self.entry:
            logging.info("Closing circuit")
            self.s.sendall(packet)
        else:
            return packet
