# TODO (Toby): I added what I need from this, so go ahead and fill out the rest
from Crypto.PublicKey import RSA


class PathingServerInterface(object):

    def __init__(self, ip, port):
        """PathingServerInterface

        args:
            ip (str): IP address of pathing server
            port (str): Port number of pathing server
        """
        pass

    def get_route(self):
        """get_route

        returns:
            list of 3 3-tuples, one for each tor router, with ip (str), port (str), and pubkey (RSA pubkey)
        """
        return [("1.1.1.1", "10", RSA.generate(2048).publickey()),
                ("2.2.2.2", "20", RSA.generate(2048).publickey()),
                ("3.3.3.3", "30", RSA.generate(2048).publickey())]
