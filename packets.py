import ipaddress
import struct


def build_domain(name):
    return b''.join(map(lambda part: struct.pack(">B", len(part)) + part.encode('utf-8'),
                 name.split('.')))

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

dns_classes = {
    1: 'IN',
    255: 'ANY'
}

to_dns_types = dict((v, k) for k, v in dns_types.items())
to_dns_classes = dict((v, k) for k, v in dns_classes.items())

class DNS_Packet:
    MESSAGE_TYPE = {'QUERY': 0, 'RESPONSE': 1}
    OPCODES = {'QUERY': 0, 'IQUERY': 1, 'STATUS': 2}
    RCODES = {'No error': 0, 'Format error': 1, 'Server failure': 2, 'Name Error': 3,
              'Not Implemented': 4, 'Refused': 5}

    def __init__(self, p_id, flags, questions, answers,
                 authority, additional):
        self.id = p_id
        self.flags = flags
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional

    @classmethod
    def build_request(cls, resolve_name, dns_type=1, dns_class=1):
        import random
        base_type, domain = DNS_Packet.__convert_domain_name__(resolve_name)

        query = Query(domain, dns_type, dns_class)
        flags = Flags(DNS_Packet.MESSAGE_TYPE['QUERY'], DNS_Packet.OPCODES['QUERY'],
                      0, 0, 0, 0, DNS_Packet.RCODES['No error'])
        return DNS_Packet(random.randint(0, 1 << 16), flags, [query], [], [], [])

    @classmethod
    def build_reply(cls, query, answers, authority, additional, rcode='No error'):
        flags = Flags(DNS_Packet.MESSAGE_TYPE['RESPONSE'],
                      query.flags.opcode,
                      0, 0, query.flags.RD, 0, DNS_Packet.RCODES[rcode])
        return DNS_Packet(query.id, flags, query.questions, answers,
                          authority, additional)

    @staticmethod
    def __convert_domain_name__(resolve_name):
        import re
        if re.match(r'\d+\.\d+\.\d+\.\d+', resolve_name):
            return 'PTR', '.'.join(reversed(resolve_name.split('.'))) + ".IN-ADDR.ARPA."
        return 'A', resolve_name if resolve_name[-1] == '.' else resolve_name + '.'

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

    def to_raw_packet(self):
        raw_flags = self.flags.to_raw_bytes()
        header = struct.pack(">HHHHHH", self.id, raw_flags, len(self.questions),
                             len(self.answers), len(self.authority), len(self.additional))

        questions = b''.join(map(lambda qe: qe.build(), self.questions))
        answers = b''.join(map(lambda rr: rr.build(), self.answers))
        authority = b''.join(map(lambda rr: rr.build(), self.authority))
        additional = b''.join(map(lambda rr: rr.build(), self.additional))

        return header + questions + answers + authority + additional

    @staticmethod
    def _parse_with_offset(cls, raw_data, offset, count):
        result = []
        for i in range(count):
            parsed, offset = cls.parse(raw_data, offset)
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

    def to_raw_bytes(self):
        return self.QR << 15 | self.opcode << 11 | self.AA << 10 | self.TC << 9 | \
               self.RD << 8 | self.RA << 7 | self.rcode


class Query:
    def __init__(self, name, q_type, q_class):
        self.name = name
        self.type = q_type
        self.q_class = q_class

    @classmethod
    def parse(cls, raw_query, offset):
        # pointer = offset
        # res = []
        # while raw_query[pointer] != 0:
        #     count = raw_query[pointer]
        #     res.append(cls.to_ascii(raw_query[pointer + 1:pointer + count + 1]))
        #     pointer += count + 1
        # name = '.'.join(res)
        name, pointer = get_domain(raw_query, offset)
        q_type, q_class = struct.unpack(">HH", raw_query[pointer: pointer + 4])
        return Query(name, q_type, q_class), pointer + 4

    def build(self):
        return build_domain(self.name) + struct.pack(">HH", self.type,
                                                     self.q_class)

    @staticmethod
    def to_ascii(data):
        # return ''.join(chr(elem) for elem in data)
        return data.decode()


class ResourceRecord:
    def __init__(self, domain, dns_type, dns_class, ttl, rdlength, rdata, raw_rdata=None):
        self.domain = domain
        self.dns_type = dns_type
        self.dns_class = dns_class
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = rdata
        self.raw_rdata = raw_rdata

    def build(self):
        return build_domain(self.domain) + struct.pack(
                   ">HHIH", self.dns_type, self.dns_class, self.ttl,
                    self.rdlength) + self.raw_rdata if self.raw_rdata else b''

    @classmethod
    def parse(cls, raw_data, offset):
        domain, offset = get_domain(raw_data, offset)
        dns_type, dns_class, ttl, rdlength = struct.unpack(">HHIH",
                                                           raw_data[offset: offset + 10])
        if dns_type in dns_types:
            key = dns_types[dns_type]
        else:
            key = "Not in list"

        rdata = cls.get_rdata(raw_data, offset + 10, rdlength, key)
        raw_rdata = raw_data[offset + 10: offset + 10 + rdlength]

        return ResourceRecord(domain, dns_type, dns_class, ttl, rdlength, rdata, raw_rdata), \
               offset + 10 + rdlength


    @classmethod
    def get_rdata(cls, raw_data, offset, length, key):
        if key in ResourceRecord.association_functions:
            function = ResourceRecord.association_functions[key]
            return function(raw_data, offset, length)
        return raw_data[offset: offset + length]

    @classmethod
    def ipv4_function(cls, raw_data, offset, length):
        return str(ipaddress.IPv4Address(raw_data[offset:offset + length]))

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
        mname, offset = get_domain(raw_data, offset)
        rname, offset = get_domain(raw_data, offset)
        serial, refresh, retry, expire, minimum = struct.unpack(">5I",
                                                                raw_data[
                                                                offset:offset + 20])

        return [('MNAME', mname), ('RNAME', rname), ('SERIAL', serial),
                ('REFRESH', refresh), ('RETRY', retry),
                ('EXPIRE', expire), ('MINIMUM', minimum)]


ResourceRecord.association_functions = {
    "A": ResourceRecord.ipv4_function,
    "AAAA": ResourceRecord.ipv6_function,
    "PTR": ResourceRecord.domain_name,
    "NS": ResourceRecord.domain_name,
    "CNAME": ResourceRecord.domain_name,
    "MX": ResourceRecord.mail_record_function,
    "SOA": ResourceRecord.soa_record_function
}


#
# def get_domain(raw_data, offset):
#     pointer, shortened_pointer = offset
#     shortened = False
#     res = []
#     while raw_data[pointer] != 0:
#         count = raw_data[pointer]
#         pointer += 1
#         if count & 0xC0 == 0xC0:
#             if not shortened:
#                 shortened_pointer += 1
#             pointer = ((count & (~0xC0)) << 8) + raw_data[pointer]
#             shortened = True
#             continue
#         res.append(raw_data[pointer: pointer + count].decode())
#         pointer += count
#     pointer += 1
#     name = '.'.join(res)
#     return name, shortened_pointer if shortened else pointer


def get_domain(data, offset):
    domain = ''
    offset_to_return = offset
    shortened = False
    while True:
        length = data[offset]
        offset += 1
        if length & 0xC0 == 0xC0:
            if not shortened:
                offset_to_return = offset + 1
            offset = ((length & (~0xC0)) << 8) + data[offset]
            shortened = True
        elif length & 0xC0 == 0 and length > 0:
            domain += data[offset: offset + length].decode('utf-8') + '.'
            offset += length
        else:
            return domain, offset_to_return if shortened else offset
