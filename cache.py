import abc
import time
from collections import namedtuple

dns_types = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    13: 'HINFO',
    15: 'MX',
    28: 'AAAA',
    252: 'AXFR',
    255: '*'
}


class AbstractCacheOperations:
    def __init__(self, name):
        self.name = name

    @abc.abstractmethod
    def domain_cached(self, query):
        # just a guarantee wrapper
        pass

    @abc.abstractmethod
    def get_domain_name_classes(self, query):
        pass

    @abc.abstractmethod
    def update_domain_name_class(self, query):
        # look through class name records for a class and than check each record ttl
        pass

    @abc.abstractmethod
    def insert_domain_name_class(self, query):
        # put a new resource record to a domain's name correct class
        pass

    @abc.abstractmethod
    def create_domain_name(self, query):
        # probably a trash method, but can be useful if domain is not valid and we now it
        # by asking server, for example
        pass


class Dns_Cache(AbstractCacheOperations):
    CacheRecord = namedtuple('CacheRecord', 'record time')

    def __init__(self, database_name):
        super().__init__(database_name)
        # simple one session implementation using pure python dictionary
        self.cache = dict()

    def update_domain_name_class(self, query):
        # cleaning records which have old ttl
        if self.domain_cached(query):
            for type in self.cache[query.name]:
                valid_records = []
                for cache_record in self.cache[query.name][type]:
                    time_elapsed = round(time.time() - cache_record.time)
                    cache_record.record.ttl -= time_elapsed
                    if cache_record.record.ttl > 0:
                        valid_records.append(cache_record)
                self.cache[query.name][type] = valid_records

    def create_domain_name(self, query):
        if not self.domain_cached(query):
            self.cache[query.name] = {}

    def get_domain_name_classes(self, query):
        if not self.domain_cached(query):
            raise KeyError("No such domain record - {}".format(query.name))
        return self.cache[query.name]

    def insert_domain_name_class(self, query):
        if not self.domain_cached(query):
            raise KeyError("No such domain name record - {}".format(query.name))
        classes = self.cache[query.name]
        if query.query_type not in classes:
            # we provide a list, however it is optional and maybe set is okay
            classes[query.type] = []
            return True
        return False

    # TODO
    # a function, where cache decide - has it or not this specific query in
    # + updates (cleaning cache)
    def process_query(self, query):
        self.update_domain_name_class(query)
        if not self.domain_cached(query):
            return None
        available_records = self.cache[query.name][query.type]
        if available_records:
            return [record.record for record in available_records]

    # TODO
    # main function where all logic of adding must be implemented
    def insert_packet_data(self, answer_packet):
        answers = answer_packet.answers
        authority = answer_packet.authority
        additional = answer_packet.additional
        domain = answer_packet.questions[0].name
        for records in [answers, authority, additional]:
            self._insert_records(records, domain)

    def domain_cached(self, query):
        return query.name in self.cache

    def _insert_records(self, records, domain):
        for record in records:
            cache_record = self.CacheRecord(record, time.time())
            if not domain in self.cache:
                self._initialize_domain(domain)
            self.cache[domain][record.dns_type].append(cache_record)

            if not record.domain in self.cache:
                self.cache[record.domain] = {}
            self.cache[record.domain][record.dns_type] = [cache_record]

    def _initialize_domain(self, domain):
        self.cache[domain] = {}
        for type in dns_types:
            self.cache[domain][type] = []

