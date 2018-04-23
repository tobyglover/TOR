
import sys
import logging
from Crypt import Crypt, Symmetric
from Crypto.PublicKey import RSA
import socket
import struct

circuit_logger = logging.getLogger("Circuit")
circuit_logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
circuit_logger.addHandler(ch)


class Circuit(object):

    def __init__(self, cid, is_pf):
        self.cid = cid
        self.is_pf = is_pf
        self.pubkey = None
        self.name = cid.encode("hex")[:8]

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
        circuit_logger.debug("Authenticating header...")
        crypt.setPublicKey(self.pubkey)
        crypt.auth(header, hsh)
        circuit_logger.debug("Header authenticated!")


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
            circuit_logger.debug("Building PFCircuit from string")
            self.pubkey = RSA.importKey(from_string)
        else:
            circuit_logger.debug("Building PFCircuit from args")
            self.pubkey = RSA.importKey(pubkey)

    def export(self):
        circuit_logger.debug("Exporting PFCircuit")
        return self.pubkey.exportKey()


class ClientCircuit(Circuit):
    EXIT = "EXIT"

    def __init__(self, cid, client_symkey, crypt, from_string=None):
        super(ClientCircuit, self).__init__(cid, False)
        self.client_symkey = client_symkey
        self.crypt = crypt

        if from_string:
            circuit_logger.debug("Initializing ClientCircuit from string")
            self.is_exit, public_key, ip, self.port, self.prev_symkey, self.next_symkey = \
                struct.unpack('?%ds4sl16s16s' % self.crypt.PUB_DER_LEN, from_string)
            self.crypt.public_key = RSA.importKey(public_key)
            self.ip = socket.inet_ntoa(ip)

            self.prev_sym = Symmetric(self.prev_symkey)
            self.next_sym = Symmetric(self.next_symkey)
            if self.is_exit:
                circuit_logger.debug("Initialized exit node! *****")
        else:
            circuit_logger.debug("Initializing new ClientCircuit")

        self.client_sym = Symmetric(self.client_symkey, cid)
        self.pubkey = crypt.public_key

    def export(self):
        circuit_logger.debug("Exporting ClientCircuit")
        return struct.pack('?%ds4sl16s16s' % self.crypt.PUB_DER_LEN, self.is_exit,
                           self.pubkey.exportKey('DER'), socket.inet_aton(self.ip),
                           self.port, self.prev_symkey, self.next_symkey)

    @staticmethod
    def _pull(sock, length):
        circuit_logger.debug("Pulling message of length %d" % length)
        message = ''
        while len(message) < length:
            message += sock.recv(length - len(message))
        return message

    def _get_payload(self, sock, sym):
        headers = self._pull(sock, self.client_sym.FULL_HEADER)
        crypt_header, header, body = sym.unpack_payload(headers)
        sym.absorb_crypto_header(crypt_header)
        l, status = sym.decrypt_header(header)
        body = sym.decrypt_body(self._pull(sock, l))
        return body, status

    def build_circuit(self, prev_sock):
        """build_circuit

        Builds a circuit from the client initialization

        Args:
            prev_sock (socket.socket): socket connection to the previous hop
        """
        body, status = self._get_payload(prev_sock, self.client_sym)  # TODO: handle bad status

        der_len = Crypt().PUB_DER_LEN
        raw_clientkey, body = body[:der_len], body[der_len:]
        self.pubkey = RSA.importKey(raw_clientkey)
        self.prev_symkey, self.next_symkey, next_ip, self.port, next_payload = \
            struct.unpack(">16s16s4sl%ds" % (max((len(body) - 40), 0)), body)
        self.ip = socket.inet_ntoa(next_ip)

        self.prev_sym = Symmetric(self.prev_symkey)

        if self.port == -1:
            self.is_exit = True
            circuit_logger.debug("Built exit node! *****")
            payload = self.client_sym.encrypt_payload('', 'OKOK')
            payload = self.prev_sym.encrypt_payload(payload, 'OKOK')
        else:
            self.is_exit = False
            self.next_sym = Symmetric(self.next_symkey)

            circuit_logger.info("Connecting to %s:%d" % (self.ip, self.port))
            next_sock = socket.socket()
            next_sock.connect((self.ip, self.port))
            next_sock.sendall(next_payload)

            circuit_logger.info("Getting response from %s:%d" % (self.ip, self.port))
            payload, status = self._get_payload(next_sock, self.next_sym)  # TODO: handle bad status
            payload = self.client_sym.encrypt_payload(payload, 'OKOK')
            payload = self.prev_sym.encrypt_payload(payload, 'OKOK')

        prev_sock.sendall(payload)

    def _forward_payload(self, prev_sock, payload):
        """forward_payload

        Forwards a payload to the next router/destination

        Args:
            prev_sock (socket.socket): socket connection to the previous hop
        """
        next_sock = socket.socket()

        if self.is_exit:
            ip, self.port, payload = struct.unpack(">4sl%ds" % (len(payload) - 8), payload)
            self.ip = socket.inet_ntoa(ip)
            next_sock.connect((self.ip, self.port))
            circuit_logger.info("Connecting to target server %s:%d" % (self.ip, self.port))
        else:
            circuit_logger.info("Connecting to next router %s:%d" % (self.ip, self.port))
            next_sock.connect((self.ip, self.port))

        next_sock.sendall(payload)

        circuit_logger.info("Getting response from %s:%d" % (self.ip, self.port))
        if self.is_exit:
            payload = ''
            chunk = 'asdf'
            next_sock.settimeout(1)
            while len(chunk) > 0:
                try:
                    chunk = next_sock.recv(1024)
                except socket.timeout:
                    chunk = ''
                except Exception:
                    circuit_logger.warning("Received exception while pulling")
                    payload = ''
                    chunk = ''
                logging.debug("Received chunk from website (%dB)" % len(chunk))
                payload += chunk
            next_sock.settimeout(None)
        else:
            payload, status = self._get_payload(next_sock, self.next_sym)  # TODO: handle bad status

        payload = self.client_sym.encrypt_payload(payload, 'OKOK')
        payload = self.prev_sym.encrypt_payload(payload, 'OKOK')
        prev_sock.sendall(payload)

    def _close_circuit(self, prev_sock, payload):

        if self.is_exit:
            payload = ""
        else:
            next_sock = socket.socket()
            circuit_logger.info("Connecting to next router %s:%d" % (self.ip, self.port))
            next_sock.connect((self.ip, self.port))
            next_sock.sendall(payload)

            circuit_logger.info("Getting response from %s:%d" % (self.ip, self.port))
            payload, status = self._get_payload(next_sock, self.next_sym)  # TODO: handle bad status

        payload = self.client_sym.encrypt_payload(payload, 'OKOK')
        payload = self.prev_sym.encrypt_payload(payload, 'OKOK')
        prev_sock.sendall(payload)

    def handle_connection(self, prev_sock):
        payload, status = self._get_payload(prev_sock, self.client_sym)  # TODO: handle bad status

        if status == self.EXIT:
            self._close_circuit(prev_sock, payload)
        else:
            self._forward_payload(prev_sock, payload)
        return status
