import ipaddress
import struct


class DNS_Packet:
    def __init__(self, p_id, flags, questions, answers,
                 authority, additional):
        self.id = p_id
        self.flags = flags
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional

    @classmethod
    def parse(cls, raw_data):
        offset = 12
        p_id, flags, questions_count, answers_count, authority_count, \
        additional_count = struct.unpack(">HHHHHH", raw_data[:offset])
        flags = Flags.parse(flags)

        questions, offset = DNS_Packet._parse_with_offset(Query, raw_data, offset,
                                                          questions_count)

        answers, offset = DNS_Packet._parse_with_offset(ResourceRecord, raw_data, offset,
                                                        answers_count)

        authority, offset = DNS_Packet._parse_with_offset(ResourceRecord, raw_data,
                                                          offset,
                                                          authority_count)

        additional, offset = DNS_Packet._parse_with_offset(ResourceRecord, raw_data,
                                                           offset,
                                                           additional_count)
        return DNS_Packet(p_id, flags, questions, answers, authority, additional)

    @staticmethod
    def _parse_with_offset(cls, raw_data, offset, count):
        result = []
        for i in range(count):
            parsed, offset = cls.parse(raw_data, count)
            result.append(parsed)
        return result, offset


class Flags:
    def __init__(self, QR, opcode, AA, TC, RD, RA, rcode):
        self.QR = QR
        self.opcode = opcode
        self.AA = AA
        self.TC = TC
        self.RD = RD
        self.RA = RA
        self.rcode = rcode

    @classmethod
    def parse(cls, raw_flags):
        QR = raw_flags >> 15
        opcode = (raw_flags >> 11) & 0xF
        AA = raw_flags >> 10 & 0x1
        TC = raw_flags >> 9 & 0x1
        RD = raw_flags >> 8 & 0x1
        RA = raw_flags >> 7 & 0x1
        rcode = raw_flags & 0xF
        return Flags(QR, opcode, AA, TC, RD, RA, rcode)


class Query:
    query_type = {
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

    query_class = {
        1: 'IN',
        255: 'ANY'
    }

    def __init__(self, name, q_type, q_class):
        self.name = name
        self.type = q_type
        self.q_class = q_class

    @classmethod
    def parse(cls, raw_query, offset):
        pointer = offset
        res = []
        while raw_query[pointer] != 0:
            count = raw_query[pointer]
            res.append(cls.to_ascii(raw_query[pointer + 1:pointer + count + 1]))
            pointer += count + 1
        name = '.'.join(res)
        bin_type, bin_class = struct.unpack(">HH", raw_query[pointer + 1: pointer + 3])
        q_type = cls.query_type[bin_type]
        q_class = cls.query_class[bin_class]
        return Query(name, q_type, q_class), pointer + 3

    @staticmethod
    def to_ascii(data):
        return ''.join(elem.decode('ascii') for elem in data)


class ResourceRecord:
    def __init__(self, domain, dns_type, dns_class, ttl, rdlength, rdata):
        self.domain = domain
        self.dns_type = dns_type
        self.dns_class = dns_class
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = rdata

    @classmethod
    def parse(cls, raw_data, offset):
        domain, offset = get_domain(raw_data, offset)  # TODO
        dns_type, dns_class, ttl, rdlength = struct.unpack(">HHIH",
                                                           raw_data[offset: offset + 10])
        if dns_type in Query.query_type:
            key = Query.query_type[dns_type]
        else:
            key = "Not in list"

        rdata = cls.get_rdata(raw_data, offset + 10, rdlength, key)

        return ResourceRecord(domain, dns_type, dns_class, ttl, rdlength, rdata), \
               offset + 10 + rdlength

    @classmethod
    def get_rdata(cls, raw_data, offset, length, key):
        if key in ResourceRecord.association_functions:
            function = ResourceRecord.association_functions[key]
            return function(raw_data, offset, length)
        return raw_data[offset: offset + length]

    @classmethod
    def ipv4_function(cls, raw_data, offset, length):
        return str(ipaddress.IPv6Address(raw_data[offset:offset + length]))

    @classmethod
    def ipv6_function(cls, raw_data, offset, length):
        return str(ipaddress.IPv6Address(raw_data[offset:offset + length]))

    @classmethod
    def domain_name(cls, raw_data, offset, length):
        return get_domain(raw_data, offset)[0]  # TODO

    @classmethod
    def mail_record_function(cls, raw_data, offset, length):
        return [('Preference', struct.unpack(">H", raw_data[offset:offset + 2])[0]),
                ('Exchange', get_domain(raw_data, offset + 2)[0])]  # TODO

    @classmethod
    def soa_record_function(cls, raw_data, offset, length):
        mname, offset = get_domain(raw_data, offset)  # TODO
        rname, offset = get_domain(raw_data, offset)  # TODO
        serial, refresh, retry, expire, minimum = struct.unpack(">5I",
                                                                raw_data[
                                                                offset:offset + 20])

        return [('MNAME', mname), ('RNAME', rname), ('SERIAL', serial),
                ('REFRESH', refresh), ('RETRY', retry),
                ('EXPIRE', expire), ('MINIMUM', minimum)]

    association_functions = {
        "A": ipv4_function,
        "AAAA": ipv6_function,
        "PTR": domain_name,
        "NS": domain_name,
        "CNAME": domain_name,
        "MX": mail_record_function,
        "SOA": soa_record_function
    }
