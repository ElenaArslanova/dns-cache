import socket
import sys
from cache import Dns_Cache
from multiprocessing.dummy import Pool as ThreadPool
from select import select


class Dns_Server:
    def __init__(self, hello_word="Hello! Ready for a job"):
        self.welcome = hello_word
        self.cache = None
        self.address = 'localhost'
        self.port = 53
        self.forwarder = None
        self.pool = None

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

    def set_up_cache(self, cache=None):
        if cache is None:
            self.cache = Dns_Cache(database_name="cache using python dictionary")
            # one session cache, could be replaced
        return self

    def apply_async(self, pool=None):
        if pool is None:
            self.pool = ThreadPool(processes=4)
        return self

    def __check_all_set_up__(self):
        values = self.__dict__
        for k, v in values.items():
            if v is None:
                raise Exception("{} is not defined".format(k))

    def __try_bind_connection__(self, connection):
        try:
            connection.bind((self.address, self.port))
        except socket.error:
            print("Could not bind pair ({}, {})".format(self.address, self.port))
        else:
            return True

    @classmethod
    def client_worker(cls, request):
        """
        a function to work with client - form answering packet and send it
        :param request: string domain name: google.com, www.vk.com or common
        """
        pass

    def launch(self):
        self.__check_all_set_up__()
        print(self.welcome)
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__try_bind_connection__(connection)
        while True:
            reading, _, _ = select([connection], [], [])
            if reading:
                try:
                    bin_data, address = connection.recvfrom(512)
                except socket.error:
                    print("Couldn't receive from client")



# a = Dns_Server("Hello").set_up_address().set_up_port().set_up_forwarder("google.com")

