from ctypes import *
import socket
import ipaddress
from string import printable
import struct

class IP_CType(Structure):
    _fields_ = [
        ("ihl",          c_ubyte,     4),    # 4 bit unsigned char
        ("version",      c_ubyte,     4),    # 4 bit unsigned char
        ("tos",          c_ubyte,     8),    # 1 byte char
        ("len",          c_ushort,    16),   # 2 byte unsigned short
        ("id",           c_ushort,    16),   # 2 byte unsigned short
        ("offset",       c_ushort,    16),   # 2 byte unsigned short
        ("ttl",          c_ubyte,     8),    # 1 byte char
        ("protocol_num", c_ubyte,     8),    # 1 byte char
        ("sum",          c_ushort,    16),   # 2 byte unsigned short
        ("src",          c_uint32,    32),   # 4 byte unsigned int
        ("dst",          c_uint32,    32)    # 4 byte unsigned int
    ]

    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # Human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

class IP_Struct:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # Human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print("%s No protocol for %s" % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

        mypacket = IP_CType(buff)
        print(f'{mypacket.src_address} -> {mypacket.dst_address}')