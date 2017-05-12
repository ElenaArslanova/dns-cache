import abc
import time
from collections import namedtuple
from itertools import chain

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
    def update_domain_name_class(self, query):
        # look through class name records for a class and than check each record ttl
        pass

    @abc.abstractmethod
    def insert_packet_data(self, answer_packet):
        # cache forwarder's replies
        pass

    @abc.abstractmethod
    def process_query(self, query):
        # find cached replies
        pass


class Dns_Cache(AbstractCacheOperations):
    def __init__(self, database_name):
        super().__init__(database_name)
        # simple one session implementation using pure python dictionary
        self.cache = dict()

    def update_domain_name_class(self, query):
        # cleaning records which have old ttl
        if self.domain_cached(query):
            for type in self.cache[query.name]:
                valid_records = set()
                for cache_record in self.cache[query.name][type]:
                    time_elapsed = round(time.time() - cache_record.time)
                    cache_record.record.ttl -= time_elapsed
                    if cache_record.record.ttl > 0:
                        valid_records.add(cache_record)
                self.cache[query.name][type] = valid_records


    def process_query(self, query):
        self.update_domain_name_class(query)
        if not self.domain_cached(query):
            return [], [], []
        available_records = self.cache[query.name][query.type]
        authority = self.cache[query.name]['authority']
        additional = self.cache[query.name]['additional']
        if available_records:
            return map(self._extract_records, [available_records,
                                               authority,
                                               additional])
        return [], [], []

    @staticmethod
    def _extract_records(cache_records):
        return [record.record for record in cache_records]

    def insert_packet_data(self, answer_packet):
        answers = answer_packet.answers
        authority = answer_packet.authority
        additional = answer_packet.additional
        domain = answer_packet.questions[0].name.lower()
        self._insert_records(answers)
        self.cache[domain]['authority'], \
        self.cache[domain]['additional'] = map(self._insert_records,
                                               [authority, additional])

    def domain_cached(self, query):
        return query.name in self.cache

    def _insert_records(self, records):
        cache_records = set()
        for record in records:
            record.domain = record.domain.lower()
            cache_record = CacheRecord(record, time.time())
            if not record.domain in self.cache:
                self._initialize_domain(record.domain)
            self.cache[record.domain][record.dns_type].add(cache_record)
            cache_records.add(cache_record)
        return cache_records

    def _initialize_domain(self, domain):
        self.cache[domain] = {}
        for type in chain(dns_types, ['additional', 'authority']):
            self.cache[domain][type] = set()

CR = namedtuple('CR', 'record time')
class CacheRecord(CR):
    def __hash__(self):
        return hash(self.record)

    def __eq__(self, other):
        if isinstance(other, CacheRecord):
            return self.record == other.record
        return False
