from Crypt import Crypt, Symmetric
import logging
import socket
from os import urandom
from Crypto.PublicKey import RSA
import struct
import sys


tri_logger = logging.getLogger("TorRouterInterface")
tri_logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
tri_logger.addHandler(ch)


class CircuitFailed(Exception):
    pass


class TorRouterInterface(object):

    CT_BLOCK_SIZE = 256
    HEADER_SIZE = 2 * CT_BLOCK_SIZE

    def __init__(self, (pkt, ip, port, router_pubkey, sid, symkey), next_router=None, is_entry=False):
        """TorRouterInterface

        Interface to Tor Router circuit

        Args:
            (pkt (str), ip (str), port (int), router_pubkey (RSA key), symkey (str)):
                Router information returned by TorPathingServer interface
            next_router (TorRouterInterface - optional):
                Next Tor router to wrap/peel onion. Must include unless router is exit node
            is_entry (bool - optional): Set to True if router is entry node
        """
        self.pkt = pkt
        self.ipp = (ip, port)
        self.router_pubkey = router_pubkey
        self.sid = sid

        self.client_symkey = symkey
        self.resp_symkey = symkey
        self.next_symkey = None
        self.prev_symkey = None

        self.next_router = next_router
        self.s = socket.socket()

        self.is_entry = is_entry
        self.is_exit = False if next_router else True

        self.client_key = Crypt().generate_key()
        self.crypt = Crypt(public_key=router_pubkey, private_key=self.client_key, name="interface%d" % port,
                           debug=True)
        self.client_sym = Symmetric(self.client_symkey, sid)
        self.resp_sym = Symmetric(self.resp_symkey)

    def _keep_alive(self):
        pass # TODO: add keep alive

    def _connect(self):
        self.s = socket.socket()
        self.s.connect(self.ipp)

    def _send(self, payload):
        logging.info("Sending packet")
        self._connect()
        self.s.sendall(payload)

    def _pull(self, length):
        message = ''
        while len(message) < length:
            message += self.s.recv(length - len(message))
        return message

    def _recv(self):
        headers = self._pull(self.client_sym.CRYPT_HEADER_LEN + self.client_sym.HEADER_LEN)
        crypt_header, header, _ = self.resp_sym.unpack_payload(headers)

        self.resp_sym.absorb_crypto_header(crypt_header)
        l, status = self.resp_sym.decrypt_header(header)
        return self.resp_sym.decrypt_body(self._pull(l))

    def peel_onion(self, onion):
        crypt_header, header, body = self.client_sym.unpack_payload(onion)
        self.client_sym.absorb_crypto_header(crypt_header)
        l, status = self.client_sym.decrypt_header(header)

        if status != "OKOK":
            raise CircuitFailed

        logging.debug("PO - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
        body = self.client_sym.decrypt_body(body)

        if self.is_exit:
            return body
        return self.next_router.peel_onion(body)

    def establish_circuit(self, prev_symkey=None):
        """establish_circuit

        Establishes a Tor circuit

        Args:
            prev_symkey (str - optional): symkey of last Tor router - do not set externally

        Raises:
            CircuitFailed: If connection to circuit failed
        """
        self.prev_symkey = prev_symkey or self.client_symkey

        payload = self.pkt
        if self.is_exit:
            header = self.client_key.publickey().exportKey("DER")
            header += struct.pack(">16s16s4sl", prev_symkey, "\x00" * 16, "\x00" * 4, -1)
            # header = struct.pack(">16")
            payload += self.client_sym.encrypt_payload(header, "EXIT")
        else:
            self.next_symkey = self.client_sym.generate()
            header = self.client_key.publickey().exportKey("DER")
            next_payload = self.next_router.establish_circuit(self.next_symkey)
            body = struct.pack(">16s16s4sL%ds" % len(next_payload), self.prev_symkey,
                                  self.next_symkey, socket.inet_aton(self.next_router.ipp[0]),
                                  self.next_router.ipp[1], next_payload)
            # print len(body)
            header += body
            p2 = self.client_sym.encrypt_payload(header, "ESTB")
            payload += p2
            tri_logger.debug("Sending header '%s...%s'" % (p2.encode('hex')[:8],
                                                       p2.encode('hex')[self.client_sym.FULL_HEADER - 8:self.client_sym.FULL_HEADER]))

        if not self.is_entry:
            return payload

        tri_logger.info("Sending payload to %s:%d" % self.ipp)
        self._send(payload)
        response = self._recv()
        self.peel_onion(response)

    def make_request(self, url, request):
        """make_request

        Sends a request to a target url through the Tor network and returns the response

        Args:
            url (str): Top level URL of target server formatted as "IP:PORT"
            request (str): Body of request to target server

        Returns:
            (str): Plaintext response from server

        Raises:
            CircuitFailed: If connection to circuit failed
        """

        url_port = url.split(":")
        ip = socket.gethostbyname(url_port[0])
        port = int(url_port[1]) if len(url_port) == 2 else 80

        # generate new client symkey
        self.client_symkey = urandom(16)
        self.client_sym = Symmetric(self.client_symkey, self.sid)

        payload = self.crypt.sign_and_encrypt("CLNT" + self.sid + self.client_symkey)
        if self.is_exit:
            port_bs = struct.pack("!I", port)
            payload += self.client_sym.encrypt_payload(socket.inet_aton(ip) + port_bs + request, "SEND")
        else:
            next_request = self.next_router.make_request(url, request)
            payload += self.client_sym.encrypt_payload(next_request, "SEND")

        if not self.is_entry:
            return payload

        logging.info("Requesting %s:%d" % (ip, port))
        self._send(payload)
        response = self._recv()
        return self.peel_onion(response)

    def close_circuit(self):
        """close_circuit

        Closes the established Tor circuit - must do before exiting

        Raises:
            CircuitFailed: If connection to circuit failed
        """
        # generate new client symkey
        self.client_symkey = urandom(16)
        client_sym = Symmetric(self.client_symkey, self.sid)

        payload = self.crypt.sign_and_encrypt("CLNT" + self.sid + self.client_symkey)
        if self.is_exit:
            payload += client_sym.encrypt_payload("", "EXIT")
        else:
            next_request = self.next_router.close_circuit()
            payload += client_sym.encrypt_payload(next_request, "EXIT")

        if not self.is_entry:
            return payload

        logging.info("Sending packet")
        self._send(payload)
        response = self._recv()
        self.peel_onion(response)


class TestTorRouterInterface(object):

    CT_BLOCK_SIZE = 256
    HEADER_SIZE = 2 * CT_BLOCK_SIZE

    def __init__(self, (pkt, ip, port, tor_pubkey, sid, symkey), next_router=None,
                 is_entry=False, is_exit=False, router_key=None, server_pubkey=None):
        self.pkt = pkt
        self.ipp = (ip, port)
        self.tor_pubkey = tor_pubkey
        self.sid = sid
        self.client_symkey = symkey
        self.next_symkey = None
        self.prev_symkey = None
        self.next_router = next_router
        self.is_entry = is_entry
        self.is_exit = is_exit
        self.router_key = router_key
        self.client_key = Crypt().generate_key()
        self.server_pubkey = server_pubkey
        self.local_crypt = Crypt(public_key=router_key.publickey(), private_key=self.client_key,
                                 name="local%d" % port, debug=True)
        self.router_crypt = Crypt(public_key=self.client_key.publickey(), private_key=self.router_key,
                                  name="router%d" % port, debug=True)
        self.server_crypt = Crypt(public_key=server_pubkey, private_key=self.router_key,
                                  name="server%d" % port, debug=True)

    def _keep_alive(self):
        pass

    def _handle_establishment(self, payload):
        pkt, (crypt_header, header, body) = payload[:512], Symmetric().unpack_payload(payload[512:])
        data, hsh = self.server_crypt.decrypt(pkt)
        self.server_crypt.auth(data, hsh)

        method, rid, self.recv_sid, symkey = data[:4], data[4:20], data[20:28], data[28:44]

        client_sym = Symmetric(symkey, self.recv_sid)
        client_sym.absorb_crypto_header(crypt_header)
        l, status = client_sym.decrypt_header(header)
        logging.debug("HE - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))

        body = client_sym.decrypt_body(body)
        der_len = Crypt().PUB_DER_LEN
        raw_clientkey, self.recv_prev_symkey, self.recv_next_symkey, next_payload = \
            body[:der_len], \
            body[der_len:der_len + 16], \
            body[der_len + 16:der_len + 32], \
            body[der_len + 32:]

        self.recv_client_key = RSA.importKey(raw_clientkey)

        if self.is_exit:
            response = ''
        else:
            response = self.next_router._handle_establishment(next_payload)
            next_sym = Symmetric(self.recv_next_symkey)
            crypt_header, header, body = client_sym.unpack_payload(response)
            next_sym.absorb_crypto_header(crypt_header)
            l, status = next_sym.decrypt_header(header)
            logging.debug("H2 - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
            response = next_sym.decrypt_body(body)

        response = client_sym.encrypt_payload(response, "OKOK")

        return Symmetric(self.recv_prev_symkey).encrypt_payload(response, "OKOK")

    def establish_circuit(self, prev_symkey=None):
        sym = Symmetric(self.client_symkey, self.sid)
        self.prev_symkey = prev_symkey or self.client_symkey

        if self.is_exit:
            payload = self.pkt
            payload += sym.encrypt_payload(self.client_key.publickey().exportKey("DER") + prev_symkey, "EXIT")
        else:
            payload = self.pkt

            self.next_symkey = sym.generate()
            next_payload = self.next_router.establish_circuit(self.next_symkey)
            payload += sym.encrypt_payload(self.client_key.publickey().exportKey("DER") + self.prev_symkey +
                                           self.next_symkey + next_payload, "ESTB")

        if not self.is_entry:
            return payload

        response = self._handle_establishment(payload)
        self.resp_symkey = self.client_symkey
        resp_sym = Symmetric(self.resp_symkey)
        crypt_header, header, body = resp_sym.unpack_payload(response)

        resp_sym.absorb_crypto_header(crypt_header)
        l, status = resp_sym.decrypt_header(header)
        logging.debug("EC - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
        body = resp_sym.decrypt_body(body)

        return self.peel_onion(body)

    def peel_onion(self, onion):
        sym = Symmetric(self.client_symkey, self.sid)
        crypt_header, header, body = sym.unpack_payload(onion)
        sym.absorb_crypto_header(crypt_header)
        l, status = sym.decrypt_header(header)
        logging.debug("PO - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
        body = sym.decrypt_body(body)

        if self.is_exit:
            return body
        return self.next_router.peel_onion(body)

    def _handle_request(self, payload):
        pkt, (crypt_header, header, body) = payload[:512], Symmetric().unpack_payload(payload[512:])
        data, hash = self.router_crypt.decrypt(pkt)
        self.router_crypt.auth(data, hash)

        method, sid, symkey = data[:4], data[4:12], data[12:]
        assert sid == self.recv_sid

        client_sym = Symmetric(symkey, sid)
        client_sym.absorb_crypto_header(crypt_header)
        l, status = client_sym.decrypt_header(header)
        logging.debug("HR - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))

        body = client_sym.decrypt_body(body)

        if self.is_exit:
            ip_raw, port, request = struct.unpack("!4sI%ds" % (len(body) - 8), body)
            ip = socket.inet_ntoa(ip_raw)
            s = socket.socket()
            s.connect((ip, port))
            s.sendall(request)
            s.settimeout(1)
            chunk = "asdf"
            payload = ""
            need_data = True
            while len(chunk) > 0 or need_data:
                try:
                    chunk = s.recv(1024)
                except socket.timeout:
                    chunk = ''
                except socket.error:
                    payload += chunk
                    break
                logging.debug("Received chunk from website (%dB)" % len(chunk))
                payload += chunk
                if len(chunk) > 0:
                    need_data = False

            return_sym = Symmetric(self.recv_prev_symkey)
            payload = client_sym.encrypt_payload(payload, "OKOK")
            return return_sym.encrypt_payload(payload, "OKOK")

        response = self.next_router._handle_request(body)

        next_sym = Symmetric(self.recv_next_symkey)
        crypt_header, header, body = client_sym.unpack_payload(response)
        # print response
        next_sym.absorb_crypto_header(crypt_header)
        l, status = next_sym.decrypt_header(header)
        logging.debug("HR - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
        response = next_sym.decrypt_body(body)

        response = client_sym.encrypt_payload(response, "OKOK")

        ret = Symmetric(self.recv_prev_symkey).encrypt_payload(response, "OKOK")
        return ret

    def make_request(self, url, request):
        url_port = url.split(":")
        ip = socket.gethostbyname(url_port[0])
        port = int(url_port[1]) if len(url_port) == 2 else 80

        logging.info("Requesting %s:%d" % (ip, port))

        # generate new client symkey
        self.client_symkey = urandom(16)
        client_sym = Symmetric(self.client_symkey, self.sid)

        if self.is_exit:
            payload = self.local_crypt.sign_and_encrypt("CLNT" + self.sid + self.client_symkey)
            port_bs = struct.pack("!I", port)
            payload += client_sym.encrypt_payload(socket.inet_aton(ip) + port_bs + request, "SEND")
        else:
            payload = self.local_crypt.sign_and_encrypt("CLNT" + self.sid + self.client_symkey)
            # print payload.encode("hex")[16:32]
            next_request = self.next_router.make_request(url, request)
            # print self.ipp[1], len(payload)
            # print ("CLNT" + self.sid + self.client_symkey).encode('hex')
            payload += client_sym.encrypt_payload(next_request, "SEND")

        if not self.is_entry:
            return payload

        logging.info("Sending packet")
        response = self._handle_request(payload)
        resp_sym = Symmetric(self.resp_symkey)
        crypt_header, header, body = resp_sym.unpack_payload(response)

        # print "5", self.ipp[1], self.client_symkey.encode('hex')
        resp_sym.absorb_crypto_header(crypt_header)
        l, status = resp_sym.decrypt_header(header)
        logging.debug("MR - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
        body = resp_sym.decrypt_body(body)

        return self.peel_onion(body)

    def _handle_close(self, payload):
        pkt, (crypt_header, header, body) = payload[:512], Symmetric().unpack_payload(payload[512:])
        data, hash = self.router_crypt.decrypt(pkt)
        self.router_crypt.auth(data, hash)

        method, sid, symkey = data[:4], data[4:12], data[12:]
        assert sid == self.recv_sid

        client_sym = Symmetric(symkey, sid)
        client_sym.absorb_crypto_header(crypt_header)
        l, status = client_sym.decrypt_header(header)
        logging.debug("HC - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))

        body = client_sym.decrypt_body(body)

        if self.is_exit:
            return_sym = Symmetric(self.recv_prev_symkey)
            payload = client_sym.encrypt_payload("", "EXIT")
            return return_sym.encrypt_payload(payload, "EXIT")

        response = self.next_router._handle_close(body)

        next_sym = Symmetric(self.recv_next_symkey)
        crypt_header, header, body = client_sym.unpack_payload(response)
        next_sym.absorb_crypto_header(crypt_header)
        l, status = next_sym.decrypt_header(header)
        logging.debug("HR - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
        response = next_sym.decrypt_body(body)

        response = client_sym.encrypt_payload(response, "EXIT")
        return Symmetric(self.recv_prev_symkey).encrypt_payload(response, "EXIT")

    def close_circuit(self):
        # generate new client symkey
        self.client_symkey = urandom(16)
        client_sym = Symmetric(self.client_symkey, self.sid)

        if self.is_exit:
            payload = self.local_crypt.sign_and_encrypt("CLNT" + self.sid + self.client_symkey)
            payload += client_sym.encrypt_payload("", "EXIT")
        else:
            payload = self.local_crypt.sign_and_encrypt("CLNT" + self.sid + self.client_symkey)
            next_request = self.next_router.close_circuit()
            payload += client_sym.encrypt_payload(next_request, "EXIT")

        if not self.is_entry:
            return payload

        logging.info("Sending packet")
        response = self._handle_close(payload)
        resp_sym = Symmetric(self.resp_symkey)
        crypt_header, header, body = resp_sym.unpack_payload(response)

        # print "5", self.ipp[1], self.client_symkey.encode('hex')
        resp_sym.absorb_crypto_header(crypt_header)
        l, status = resp_sym.decrypt_header(header)
        logging.debug("CC - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
        body = resp_sym.decrypt_body(body)

        return self.peel_onion(body)
