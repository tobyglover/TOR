from Crypt import Crypt, Symmetric
import logging
import socket
from os import urandom
from Crypto.PublicKey import RSA
import struct


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

    def _pull(self, length):
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
        header = self._pull(self.HEADER_SIZE)
        num_chunks = int(self.crypt.decrypt_and_auth(header))

        onion = self._pull(num_chunks * self.CT_BLOCK_SIZE)
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
        self.local_crypt = Crypt(public_key=router_key.publickey(), private_key=self.client_key, name="local%d" % port, debug=True)
        self.router_crypt = Crypt(public_key=self.client_key.publickey(), private_key=self.router_key, name="router%d" % port, debug=True)
        self.server_crypt = Crypt(public_key=server_pubkey, private_key=self.router_key, name="server%d" % port, debug=True)

    def _keep_alive(self):
        pass

    def _handle_establishment(self, payload):
        pkt, (crypt_header, header, body) = payload[:512], Symmetric().unpack_payload(payload[512:])
        data, hash = self.server_crypt.decrypt(pkt)
        self.server_crypt.auth(data, hash)

        method, rid, self.recv_sid, symkey = data[:4], data[4:20], data[20:28], data[28:44]

        client_sym = Symmetric(symkey, self.recv_sid)
        client_sym.absorb_crypto_header(crypt_header)
        l, status = client_sym.decrypt_header(header)
        logging.debug("HE - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))

        body = client_sym.decrypt_body(body)
        DER_LEN = Crypt().PUB_DER_LEN
        raw_clientkey, self.recv_prev_symkey, self.recv_next_symkey, next_payload = \
            body[:DER_LEN], \
            body[DER_LEN:DER_LEN + 16], \
            body[DER_LEN + 16:DER_LEN + 32], \
            body[DER_LEN + 32:]

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
