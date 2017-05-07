import socket
import sys


class Dns_Server:
    def __init__(self, hello_word="Hello"):
        self.welcome = hello_word
        self.cache = None
        self.address = 'localhost'
        self.port = 53
        self.forwarder = None

    def set_up_address(self, address='localhost'):
        self.address = address
        return self

    def set_up_port(self, port=53):
        self.port = port
        return self

    def set_up_forwarder(self, forwarder):
        try:
            socket.gethostbyaddr(forwarder)
        except socket.herror:
            try:
                socket.gethostbyname(forwarder)
            except socket.gaierror:
                print("Not existing {} or not found".format(forwarder))
                sys.exit()
            else:
                self.forwarder = forwarder
        else:
            self.forwarder = forwarder
        return self

    def set_up_cache(self, cache):
        pass
        return self

    def __check_all_set_up__(self):
        values = self.__dict__
        for k, v in values.items():
            if v is None:
                raise Exception("{} is not defined".format(k))

    def launch(self):
        self.__check_all_set_up__()
        pass

Dns_Server().__check_all_set_up__()

# a = Dns_Server("Hello").set_up_address().set_up_port().set_up_forwarder("google.com")

