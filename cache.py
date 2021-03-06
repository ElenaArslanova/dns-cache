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
    def domain_cached(self, domain):
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


class DnsCache(AbstractCacheOperations):
    def __init__(self, database_name):
        super().__init__(database_name)
        # simple one session implementation using pure python dictionary
        self.cache = dict()

    def update_domain_name_class(self, query):
        # cleaning records which have old ttl
        if self.domain_cached(query.name):
            for type in self.cache[query.name]:
                valid_records = set()
                for cache_record in self.cache[query.name][type]:
                    time_elapsed = round(time.time() - cache_record.time)
                    if cache_record.record.ttl - time_elapsed > 0:
                        valid_records.add(cache_record)
                self.cache[query.name][type] = valid_records

    def process_query(self, query):
        self.update_domain_name_class(query)
        if not self.domain_cached(query.name):
            return [], [], []
        available_records, authority, additional = self._process_query(query)
        if available_records:
            return map(self._extract_records, [available_records,
                                               authority,
                                               additional])
        return [], [], []

    @staticmethod
    def _extract_records(cache_records):
        return sorted([record.record for record in cache_records],
                      key=lambda r: r.domain)

    def _get_any(self, domain):
        any = []
        for type in self.cache[domain]:
            records = self.cache[domain][type]
            if records:
                any.extend(records)
        return any

    def _process_query(self, query):
        if query.type == 255:
            return self._get_any(query.name), [], []
        return self._get_records_considering_cname(query)

    def _get_records(self, domain, type):
        if self.domain_cached(domain):
            cached = self.cache[domain]
            available_records = cached[type]
            authority = cached['authority'] - available_records
            additional = cached['additional'] - available_records
            return available_records, authority, additional
        return [], [], []

    def _get_records_considering_cname(self, query):
        records, authority, additional = [], [], []
        for name in chain((query.name,), (cname.record.rdata for cname in self.cache[query.name][5])):
            available_records, authority_r, additional_r = self._get_records(name, query.type)
            records.extend(available_records)
            authority.extend(authority_r)
            additional.extend(additional_r)
        records.extend(cname_record for cname_record in self.cache[query.name][5])
        return records, authority, additional

    def insert_packet_data(self, answer_packet):
        answers = answer_packet.answers
        authority = answer_packet.authority
        additional = answer_packet.additional
        domain = answer_packet.questions[0].name.lower()
        if domain not in self.cache:
            self._initialize_domain(domain)
        self._insert_records(answers)
        self.cache[domain]['authority'], \
        self.cache[domain]['additional'] = map(self._insert_records,
                                               [authority, additional])

    def domain_cached(self, domain):
        return domain in self.cache

    def _insert_records(self, records):
        cache_records = set()
        for record in records:
            record.domain = record.domain.lower()
            cache_record = CacheRecord(record, time.time())
            if record.domain not in self.cache:
                self._initialize_domain(record.domain)
            if record.dns_type in dns_types:
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
