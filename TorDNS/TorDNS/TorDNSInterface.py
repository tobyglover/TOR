from Crypt import Crypt
import struct
import socket
from os import urandom


class ConnectionCorrupted(Exception):
    pass


class URLNotFound(Exception):
    pass


class TorDNSInterface(object):
    RECV_LEN = 512

    def __init__(self, ip, port, pubkey):
        """TorDNSInterface

        Interface to the TorDNS service

        Args:
            ip (str): Unpacked IP address of live TorDNS server
            port (int): Port on live TorDNS server to connect to
            pubkey (Crypt-generated RSA key): Public key of the TorDNS server
        """
        self.ipp = (ip, port)
        self.prikey = Crypt().generate_key()
        self.crypt = Crypt(public_key=pubkey, private_key=self.prikey)

    def _pull(self, s, length):
        message = ''
        while len(message) < length:
            message += s.recv(length - len(message))
        return message

    def _send_recv(self, payload):
        salt = urandom(16)
        payload = self.crypt.sign_and_encrypt(salt + payload)
        sock = socket.socket()
        sock.connect(self.ipp)
        sock.sendall(payload)

        response = self._pull(sock, self.RECV_LEN)
        response = self.crypt.decrypt_and_auth(response)
        if payload != response[:16]:
            raise ConnectionCorrupted

        return response[16:]

    def register(self, ip, port):
        """register

        Registers a new funion service to the TorDNS server

        Args:
            ip (str): Unpacked IP address to register
            port (int): Port to register

        Returns:
            (str, str): Two-tuple with new .funion URL service is registered to
                        and API key for future communications with TorDNS server
        """
        payload = struct.pack(">4sL%ds" % self.crypt.PUB_DER_LEN,
                              socket.inet_aton(ip), port,
                              self.prikey.publickey().export("DER"))
        resp = self._send_recv(payload)
        return struct.unpack(">19s16s", resp)

    def update(self, ip, port, apikey):
        """update

        Updates the IP and port of a funion service

        Args:
            ip (str): New, unpacked IP address to register
            port (int): New port to register
            apikey (str): API key of funion service

        Returns:
            bool: Whether or not update was successful
        """
        payload = struct.pack(">4sL16s%ds" % self.crypt.PUB_DER_LEN,
                              socket.inet_aton(ip), port, apikey,
                              self.prikey.publickey().export("DER"))
        resp = self._send_recv(payload)
        return struct.unpack(">?", resp)

    def deregister(self, apikey):
        """deregister

        Deregisters funion service from the TorDNS service

        Args:
            apikey (str): API key of funion service

        Returns:
            bool: Whether or not update was successful
        """
        payload = struct.pack(">16s%ds" % self.crypt.PUB_DER_LEN, apikey,
                              self.prikey.publickey().export("DER"))
        resp = self._send_recv(payload)
        return struct.unpack(">?", resp)

    def lookup(self, url):
        """lookup

        Looks up the IP and port of the funion service associated with a URL

        Args:
            url (str): url of funion service to lookup

        Returns:
            (str, int): Two-tuple of the IP and port of the funion service
        """
        payload = struct.pack(">19s%ds" % self.crypt.PUB_DER_LEN, url,
                              self.prikey.publickey().export("DER"))
        resp = self._send_recv(payload)
        found, ip, port = struct.unpack(">?4sL", resp)
        if not found:
            raise URLNotFound
        return ip, port
