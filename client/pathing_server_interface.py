
# TODO (Toby): I added what I need from this, so go ahead and fill out the rest


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
            list of 3 3-tuples, one for each tor router, with ip (str), port (str), and pubkey (str)
        """
        return [("1.1.1.1", "10", "PUBKEY1"), ("2.2.2.2", "20", "PUBKEY2"), ("3.3.3.3", "30", "PUBKEY3")]
