import shelve
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
    def check_if_domain_exist(self, key):
        # just a guarantee wrapper
        pass

    @abc.abstractmethod
    def get_domain_name_classes(self, key):
        pass

    @abc.abstractmethod
    def update_domain_name_class(self, key, class_name):
        # look through class name records for a class and than check each record ttl
        pass

    @abc.abstractmethod
    def insert_domain_name_class(self, key, class_name):
        # put a new resource record to a domain's name correct class
        pass

    @abc.abstractmethod
    def create_domain_name(self, key):
        # probably a trash method, but can be useful if domain is not valid and we now it
        # by asking server, for example
        pass


class Dns_Cache(AbstractCacheOperations):
    def __init__(self, database_name):
        super().__init__(database_name)
        # simple one session implementation using pure python dictionary
        self.cache = dict()

    def update_domain_name_class(self, key, class_name):
        # cleaning records which have old ttl
        pass

    def create_domain_name(self, key):
        if self.check_if_domain_exist(key):
            return False
        self.cache[key] = {}
        return True

    def get_domain_name_classes(self, key):
        if not self.check_if_domain_exist(key):
            raise KeyError("No such domain record - {}".format(key))
        return self.cache[key]

    def insert_domain_name_class(self, key, class_name):
        if not self.check_if_domain_exist(key):
            raise KeyError("No such domain name record - {}".format(key))
        classes = self.cache[key]
        if class_name not in classes:
            # we provide a list, however it is optional and maybe set is okay
            classes[class_name] = []
            return True
        return False

    def check_if_domain_exist(self, key):
        return True if key in self.cache else False
