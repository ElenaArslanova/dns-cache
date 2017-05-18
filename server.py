import socket
import sys
import argparse
from cache import DnsCache
from itertools import zip_longest
from multiprocessing.dummy import Pool as ThreadPool
from select import select
from threading import Lock
from packets import DNS_Packet, dns_types


class DnsServer:
    def __init__(self, hello_word="Hello! Ready for a job"):
        self.welcome = hello_word
        self.cache = None
        self.address = 'localhost'
        self.port = 53
        self.forwarder = None
        self.pool = None
        self._lock = Lock()
        self._unprocessed_questions = set()

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
            self.cache = DnsCache(database_name="cache using python dictionary")
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

    def client_worker(self, request, connection):
        """
        a function to work with client - form answering packet and send it
        :param
        request is a Tuple : binary_data and address
        binary_data converted to string domain name: google.com, www.vk.com or common
        and address - sending dns reply to a client
        """
        bin_data, address = request
        query = DNS_Packet.parse(bin_data)
        query_questions = frozenset(query.questions)
        if query_questions in self._unprocessed_questions:
            return
        self._unprocessed_questions.add(query_questions)
        answers = []
        authority = []
        additional = []
        for question in query.questions:
            cache_result, c_authority, c_additional = self.cache.process_query(question)
            if not cache_result:
                replies = self.ask_forwarder(question)
                if not replies:
                    return
                print('{}, {}, {}, {}'.format(address[0], dns_types[question.type], question.name, 'forwarder'))
                self._process_forwarder_replies(replies, query, connection, address)
                self._unprocessed_questions.remove(query_questions)
                return
            answers.extend(cache_result)
            authority.extend(c_authority)
            additional.extend(c_additional)
            print('{}, {}, {}, {}'.format(address[0], dns_types[question.type], question.name, 'cache'))
        reply = DNS_Packet.build_reply(query, answers, authority, additional)
        connection.sendto(reply.to_raw_packet(), address)
        self._unprocessed_questions.remove(query_questions)

    def _insert_reply_into_cache(self, reply):
        with self._lock:
            self.cache.insert_packet_data(reply)

    @staticmethod
    def _without_errors(forwarder_reply):
        return forwarder_reply.flags.rcode == DNS_Packet.RCODES['No error']

    def _process_forwarder_replies(self, replies, query, connection, address):
        for reply in replies:
            reply.id = query.id
            connection.sendto(reply.to_raw_packet(), address)
            if self._without_errors(reply):
                self._insert_reply_into_cache(reply)

    def ask_forwarder(self, query):
        results = []
        raw = DNS_Packet.build_request(resolve_name=query.name,
                                       dns_type=query.type).to_raw_packet()
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
                        return [converted_pack]
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
                    self.pool.apply_async(self.client_worker, args=[question, connection])


def create_parser():
    parser = argparse.ArgumentParser(description='Caching DNS server')
    parser.add_argument('-p', '--port', type=int, default=53, help='listening udp port')
    parser.add_argument('-f', '--forwarder', default='8.8.8.8', help='dns forwarder[:port]')
    return parser


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    port = args.port
    params = dict(zip_longest(['forwarder', 'port'], args.forwarder.split(':'), fillvalue=port))
    server = DnsServer('Hello').set_up_address().set_up_port(int(params['port'])).set_up_forwarder(params['forwarder'])
    server.apply_async().set_up_cache().launch()
