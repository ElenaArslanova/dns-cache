import abc

class_names = {
    'A',
    'NS',
    'CNAME',
    'SOA',
    'PTR',
    'HINFO',
    'MX',
    'AAAA',
    'AXFR',
    '*'
}


class AbstractCacheOperations:
    def __init__(self, name):
        self.name = name

    @abc.abstractmethod
    def check_if_domain_exist(self, query):
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
    def __init__(self, database_name):
        super().__init__(database_name)
        # simple one session implementation using pure python dictionary
        self.cache = dict()

    def update_domain_name_class(self, query):
        # cleaning records which have old ttl
        pass

    def create_domain_name(self, query):
        if self.check_if_domain_exist(query):
            return False
        self.cache[query.name] = {}
        return True

    def get_domain_name_classes(self, query):
        if not self.check_if_domain_exist(query):
            raise KeyError("No such domain record - {}".format(query.name))
        return self.cache[query.name]

    def insert_domain_name_class(self, query):
        if not self.check_if_domain_exist(query):
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
    def evaluate_query(self, query):
        if not self.check_if_domain_exist(query):
            return False
        if query.query_type in self.cache[query.name]:
            available_records = self.cache[query.name][query.query_type]
            if len(available_records) == 0:
                return False

            pass

    # TODO
    # main function where all logic of adding must be implemented
    def insert_packet_data(self, answer_packet):
        answers = answer_packet.answers
        authority = answer_packet.authority
        additional = answer_packet.additional




    def check_if_domain_exist(self, query):
        return True if query.name in self.cache else False
