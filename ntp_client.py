#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import os
import sys
import struct
import socket
import rfc7822
import binascii

import aes_siv

from ntp import NTPPacket, NTPExtensionField,  NTPExtensionFieldType
from nts import NTSClientPacketHelper, NTSCookie
from constants import *

def main():
    argi = 1

    ipv4_only = False
    ipv6_only = False

    while argi < len(sys.argv) and sys.argv[argi].startswith('-'):
        opts = sys.argv[argi][1:]
        argi += 1
        for o in opts:
            if o == '4':
                ipv4_only = True
            elif o == '6':
                ipv6_only = True
            else:
                print("unknown option -%s" % repr(o), file = sys.stderr)
                sys.exit(1)

    if len(sys.argv) not in [ argi, argi + 2 ]:
        print("Usage: python [-46] ntp-client.py <host> <port>",
              file=sys.stderr)
        sys.exit(1)

    if ipv4_only and ipv6_only:
        print("Error: both -4 and -6 specified, use only one",
              file=sys.stderr)
        sys.exit(1)

    ntp_server = sys.argv[argi]
    argi += 1
    ntp_port = int(sys.argv[argi])
    argi += 1

    try:
        import configparser
    except ImportError:
        import ConfigParser as configparser

    import socket
    import os

    if ipv6_only:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.settimeout(1)

    req = NTPPacket()
    req.transmit_timestamp = struct.unpack('Q', os.urandom(8))[0]

    buf = req.pack()

    if 1:
        print(NTPPacket.unpack(buf))
        print()

    if 0:
        print(NTSServerPacket.unpack(buf, unpack_key = c2s_key))
        print()

    if 1:
        s = (''.join([ '%02x' % b for b in buf ]))
        print(s)

    ntp_addr = (ntp_server, ntp_port)
    print(ntp_addr)
    sock.sendto(buf, ntp_addr)

    try:
        data, addr = sock.recvfrom(65536)
    except socket.timeout:
        print("Timeout")
        return

    resp = NTPPacket.unpack(data)
    print(resp)

    if resp.origin_timestamp != req.transmit_timestamp:
        raise ValueError("transmitted origin and received transmit timestamps do not match")

if __name__ == '__main__':
    main()
