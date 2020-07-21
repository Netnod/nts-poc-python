#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import os
import sys
import struct
import socket
import rfc7822
import binascii
import random

import aes_siv

from ntp import NTPPacket, NTPExtensionField,  NTPExtensionFieldType
from nts import NTSClientPacketHelper, NTSCookie
from constants import *

def randbytes(n):
    return bytearray(random.getrandbits(8) for _ in range(n))

class NTSTSClient(object):
    def __init__(self):
        self.host = None
        self.port = None
        self.ipv4_only = False
        self.ipv6_only = False

        self.c2s_key = None
        self.s2c_key = None
        self.cookies = None

        self.debug = 0
        self.fuzz = 0
        self.uidsize = None

    def add_unique_identifier(self, req):
        n = 32
        if self.uidsize is not None:
            n = self.uidsize
            print("forcing UID length %d" % n)
        elif self.fuzz & 0x1:
            n = random.randrange(128) * 4
            print("fuzzing: random UID length %d" % n)
            
        unique_identifier = os.urandom(n)

        field = NTPExtensionField(
            NTPExtensionFieldType.Unique_Identifier,
            unique_identifier)
        req.ext.append(field)

        if self.uidsize is not None:
            field.force_size = True

        return unique_identifier

    def communicate(self):
        if self.ipv6_only:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(1)

        cookie = self.cookies[0]
        del self.cookies[0]

        req = NTSClientPacketHelper()
        req.debug = self.debug
        req.transmit_timestamp = struct.unpack('Q', os.urandom(8))[0]

        if (self.fuzz & 0x2) and random.random() < 0.1:
            print("fuzzing: skipping unique identifier")
            unique_identifier = None

        else:
            unique_identifier = self.add_unique_identifier(req)

            if (self.fuzz & 0x4) and random.random() < 0.1:
                print("fuzzing: adding one more unique identifier")
                self.add_unique_identifier(req)

            elif (self.fuzz & 0x8) and random.random() < 0.1:
                print("fuzzing: duplicating unique identifier")
                req.ext.append(req.ext[-1])

        if (self.fuzz & 0x10) and random.random() < 0.1:
            print("fuzzing: skipping cookie")
        else:
            if (self.fuzz & 0x20) and random.random() < 0.1:
                n = 1 + random.randrange(1024)
                print("fuzzing: adding %d bytes of random data to cookie" % n)
            else:
                n = 0
            req.ext.append(NTPExtensionField(
                NTPExtensionFieldType.NTS_Cookie,
                cookie + randbytes(n)))

            if (self.fuzz & 0x40) and random.random() < 0.1:
                print("fuzzing: duplicating cookie")
                req.ext.append(req.ext[-1])

        while (self.fuzz & 0x80) and random.random() < 0.3:
            t = random.randrange(65536)
            n = random.randrange(1024)
            print("fuzzing: adding field 0x%04x of length %d" % (t,n))
            req.ext.append(NTPExtensionField(t, randbytes(n)))

        req.pack_key = self.c2s_key
        req.enc_ext = [ ]

        while (self.fuzz & 0x100) and random.random() < 0.3:
            t = random.randrange(65536)
            n = random.randrange(1024)
            print("fuzzing: adding encrypted field 0x%04x of length %d" % (t,n))
            req.enc_ext.append(NTPExtensionField(t, randbytes(n)))

        if self.fuzz & 0x200:
            n = random.randrange(len(self.cookies)-1)
            if n:
                print("fuzzing: throwing away %d cookie placeholders" % n)
                del self.cookies[-n:]

        for i in range(8 - len(self.cookies) - 1):
            cookie_len = len(cookie)

            if (self.fuzz & 0x400) and random.random() < 0.1:
                n = 1 + random.randrange(1024)
                print("fuzzing: adding %d bytes of random data to cookie placeholder %d" % (n, i))
            elif (self.fuzz & 0x800) and random.random() < 0.1:
                n = 1 + random.randrange(cookie_len-1)
                print("fuzzing: cutting %d bytes off end of cookie placeholder %d" % (n, i))
                cookie_len -= n
                n = 0
            else:
                n = 0
            req.ext.append(NTPExtensionField(NTPExtensionFieldType.NTS_Cookie_Placeholder, bytes(bytearray(cookie_len)) + randbytes(n)))

        if (self.fuzz & 0x1000):
            print("fuzzing: shuffling order of extension fields")
            random.shuffle(req.ext)

        buf = req.pack()

        if self.debug:
            print(NTPPacket.unpack(buf))
            print()

        if 0:
            print(NTSServerPacket.unpack(buf, unpack_key = self.c2s_key))
            print()

        if 1 and self.debug:
            s = (''.join([ '%02x' % b for b in buf ]))
            print(s)

        nts_addr = (self.host, self.port)
        if self.debug:
            print(nts_addr)
        sock.sendto(buf, nts_addr)

        try:
            data, addr = sock.recvfrom(65536)
        except socket.timeout as e:
            return e

        resp = NTSClientPacketHelper.unpack(data, unpack_key = self.s2c_key)
        if self.debug:
            print(resp)

        if resp.origin_timestamp != req.transmit_timestamp:
            raise ValueError("transmitted origin and received transmit timestamps do not match")
        if resp.unique_identifier is None:
            if self.debug:
                print("Warning: no unique identifier returned")
        elif resp.unique_identifier != unique_identifier:
            raise ValueError("transmitted and received unique identifiers do not match")

        if self.debug:
            print("nts_cookies", len(resp.nts_cookies))
            if resp.enc_ext is None:
                print("enc_ext", None)
            else:
                print("enc_ext", len(resp.enc_ext))
            if resp.unauth_ext is None:
                print("unath_ext", None)
            else:
                print("unath_ext", len(resp.unauth_ext))

        self.cookies.extend(resp.nts_cookies)

        if resp.stratum == 0:
            return("got kiss of death")

        return None

def main():
    random.seed()

    client = NTSTSClient()

    try:
        import configparser
    except ImportError:
        import ConfigParser as configparser

    config = configparser.RawConfigParser()
    config.read('client.ini')

    client.host = config.get('ntpv4', 'server').strip()
    client.port = int(config.get('ntpv4', 'port'))

    argi = 1

    while argi < len(sys.argv) and sys.argv[argi].startswith('-'):
        opts = sys.argv[argi][1:]
        argi += 1
        for o in opts:
            if o == '4':
                client.ipv4_only = True
            elif o == '6':
                client.ipv6_only = True
            elif o == 'd':
                client.debug += 1
            elif o == 'z':
                client.fuzz = int(sys.argv[argi], 16)
                argi += 1
            elif o == 'u':
                client.uidsize = int(sys.argv[argi])
                argi += 1
            else:
                print("unknown option -%s" % repr(o), file = sys.stderr)
                sys.exit(1)

    if len(sys.argv) not in [ argi, argi + 2 ]:
        print("Usage: python [-46] nts-client.py <host> <port>",
              file=sys.stderr)
        sys.exit(1)

    if client.ipv4_only and client.ipv6_only:
        print("Error: both -4 and -6 specified, use only one",
              file=sys.stderr)
        sys.exit(1)

    if argi < len(sys.argv):
        client.host = sys.argv[argi]
        argi += 1
        client.port = int(sys.argv[argi])
        argi += 1

    client.c2s_key = binascii.unhexlify(config.get('keys', 'c2s'))
    client.s2c_key = binascii.unhexlify(config.get('keys', 's2c'))

    client.cookies = [ binascii.unhexlify(v) for k, v in sorted(config.items('cookies')) ]

    if not client.cookies:
        raise ValueError("no cookies in client.ini")

    e = client.communicate()
    if e:
        print(e)
        sys.exit(1)

    config.remove_section('cookies')
    config.add_section('cookies')
    for k, v in enumerate(client.cookies):
        config.set('cookies', str(k), binascii.hexlify(v).decode('ascii'))

    with open('client.ini', 'w') as f:
        config.write(f)

if __name__ == '__main__':
    main()
