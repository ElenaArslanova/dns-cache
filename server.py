import socket
import sys
from cache import Dns_Cache
from multiprocessing.dummy import Pool as ThreadPool
from select import select
from threading import Lock
from packets import DNS_Packet


class Dns_Server:
    def __init__(self, hello_word="Hello! Ready for a job"):
        self.welcome = hello_word
        self.cache = None
        self.address = 'localhost'
        self.port = 53
        self.forwarder = None
        self.pool = None
        self.lock = Lock()

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

    def client_worker(self, request):
        """
        a function to work with client - form answering packet and send it
        :param
        request is a Tuple : binary_data and address
        binary_data converted to string domain name: google.com, www.vk.com or common
        and address - sending dns reply to a client
        """
        bin_data, address = request
        query = DNS_Packet.parse(bin_data)
        for question in query.questions:
            pass

    def ask_forwarder(self, query):
        results = []
        raw = DNS_Packet.build_request(resolve_name=query.name,
                                       dns_type=query.query_type).to_raw_packet()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(raw, (self.forwarder, 53))
            while True:
                read, _, _ = select([sock], [], [], 1)
                if read:
                    raw_data = sock.recv(512)
                    converted_pack = DNS_Packet.parse(raw_data)
                    if converted_pack.flags.TC:
                        results.append(converted_pack)
                        continue
                    else:
                        break
                else:
                    break
        return results



    def launch(self):
        self.__check_all_set_up__()
        print(self.welcome)
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__try_bind_connection__(connection)
        while True:
            reading, _, _ = select([connection], [], [],1)
            if reading:
                try:
                    question = connection.recvfrom(512)
                except socket.error:
                    print("Couldn't receive from client")
                else:
                    self.pool.apply_async(self.client_worker, args=(question))

# a = Dns_Server("Hello").set_up_address().set_up_port().set_up_forwarder("google.com")
