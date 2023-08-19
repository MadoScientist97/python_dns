from dataclasses import dataclass
import random
import dataclasses
import struct
import socket
import sys

# Global Configs
random.seed(1)
TYPE_A = 1
CLASS_IN = 1

@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

@dataclass
class DNSQuery:
    name: bytes
    type_: int
    class_: int

def header_to_bytes(header):
    fields = dataclasses.astuple(header)
    # 6 H's because 6 fields
    return struct.pack("!HHHHHH", *fields)

def query_to_bytes(query):
    return query.name + struct.pack("!HH", query.type_, query.class_)

def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"

def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65353)
    RECURSION_DESIRED = 1 << 8
    RECURSION_NOT_DESIRED = 0
    header = DNSHeader(id = id, num_questions=1, flags=RECURSION_NOT_DESIRED)
    query = DNSQuery(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + query_to_bytes(query)
