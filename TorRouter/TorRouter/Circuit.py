
import sys
import logging
from Crypt import Crypt, Symmetric
from Crypto.PublicKey import RSA
import socket
import struct

logger = logging.getLogger("Circuit")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


class Circuit(object):

    def __init__(self, cid, is_pf):
        self.cid = cid
        self.is_pf = is_pf
        self.pubkey = None

    def export(self):
        raise NotImplemented

    def auth_header(self, header, hsh, crypt):
        """auth_header

        Args:
            header (str): header to authenticate
            crypt (Crypt): Crypt object to authenticate with

        Raises:
            ValueError: if authentication fails
        """
        logger.debug("Authenticating header...")
        crypt.setPublicKey(self.pubkey)
        crypt.auth(header, hsh)
        logger.debug("Header authenticated!")


class PFCircuit(Circuit):

    def __init__(self, cid, from_string=None, pubkey=None):
        """PFCircuit

        Interface to a Pathfinding Circuit

        Args:
            cid (str): circuit ID of the Pathfinding Circuit
            from_string (str): stored SQL string to import public key from
            pubkey (RSA.RsaKey): public RSA key of Pathfinding Server
        """
        super(PFCircuit, self).__init__(cid, True)

        if from_string:
            logger.debug("Building PFCircuit from string")
            self.pubkey = RSA.importKey(from_string)
        else:
            logger.debug("Building PFCircuit from string")
            self.pubkey = pubkey

    def export(self):
        logger.debug("Exporting PFCircuit")
        return self.pubkey.exportKey()


class ClientCircuit(Circuit):

    def __init__(self, cid, client_symkey, crypt, from_string=None):
        super(ClientCircuit, self).__init__(cid, False)
        self.client_symkey = client_symkey
        self.crypt = crypt

        if from_string:
            logger.debug("Initializing ClientCircuit from string")
            self.is_exit, public_key, ip, self.port, self.prev_symkey, self.next_symkey = \
                struct.unpack('?%ds4sL16s16s' % self.crypt.PUB_DER_LEN, from_string)
            self.crypt.public_key = RSA.importKey(public_key)
            self.ip = socket.inet_ntoa(ip)

            self.prev_sym = Symmetric(self.prev_symkey)
            self.next_sym = Symmetric(self.next_symkey)
        else:
            logger.debug("Initializing new ClientCircuit")

        self.client_sym = Symmetric(self.client_symkey, cid)
        self.pubkey = crypt.public_key

    def export(self):
        logger.debug("Exporting ClientCircuit")
        return struct.pack('?%ds4sL16s16s' % self.crypt.PUB_DER_LEN, self.is_exit,
                           self.pubkey.exportKey('DER'), socket.inet_aton(self.ip),
                           self.port, self.prev_symkey, self.next_symkey)

    @staticmethod
    def pull(sock, length):
        logger.debug("Pulling message of length %d" % length)
        message = ''
        while len(message) < length:
            message += sock.recv(length - len(message))
        return message

    def build_circuit(self, prev_sock):
        """build_circuit

        Builds a circuit from the client initialization

        Args:
            prev_sock (socket.socket): socket connection to the previous hop
        """
        headers = self.pull(prev_sock, self.client_sym.FULL_HEADER)
        crypt_header, header, _ = Symmetric().unpack_payload(headers)
        self.client_sym.absorb_crypto_header(crypt_header)
        l, status = self.client_sym.decrypt_header(header)

        body = self.pull(prev_sock, l)
        body = self.client_sym.decrypt_body(body)

        der_len = Crypt().PUB_DER_LEN
        raw_clientkey, body = body[:der_len], body[der_len:]
        self.pubkey = RSA.importKey(raw_clientkey)
        self.prev_symkey, self.next_symkey, next_ip, self.port, next_payload = \
            struct.unpack("16s16s4sL%ds" % max((len(body) - 40), 0), body)

        self.prev_sym = Symmetric(self.prev_symkey)

        if len(next_ip) == 0:
            self.is_exit = True
            payload = self.client_sym.encrypt_payload('', 'OKOK')
            payload = self.prev_sym.encrypt_payload(payload, 'OKOK')
        else:
            self.is_exit = False
            self.ip = socket.inet_ntoa(next_ip)
            self.next_sym = Symmetric(self.next_symkey)

            next_sock = socket.socket()
            next_sock.connect((self.ip, self.port))
            next_sock.sendall(next_payload)

            headers = self.pull(next_sock, self.client_sym.FULL_HEADER)
            crypt_header, header, _ = Symmetric().unpack_payload(headers)
            self.next_sym.absorb_crypto_header(crypt_header)
            l, status = self.next_sym.decrypt_header(header)

            payload = self.pull(next_sock, l)
            # TODO: handle bad status
            payload = self.next_sym.decrypt_body(payload)
            payload = self.client_sym.encrypt_payload(payload, 'OKOK')
            payload = self.prev_sym.encrypt_payload(payload, 'OKOK')

        prev_sock.sendall(payload)

    def forward_payload(self):
        pass
