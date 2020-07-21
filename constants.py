#! /usr/bin/python
from __future__ import division, print_function, unicode_literals

import enum

def _enum_range(d, name, start, end):
    for i in range(start, end):
        d['%s(%u)' % (name, i)] = i

# Constants from RFC5905 Network Time Protocol Version 4

@enum.unique
class LeapIndicator(enum.IntEnum):
    NORMAL 		= 0     # no warning
    LAST_61 		= 1     # last minute of the day has 61 seconds
    LAST_59 		= 2     # last minute of the day has 59 seconds
    UNKNOWN 		= 3     # unknown (clock unsynchronized)

@enum.unique
class Mode(enum.IntEnum):
    RESERVED		= 0     # reserved
    SYMMETRIC_ACTIVE 	= 1     # symmetric active
    SYMMETRIC_PASSIVE 	= 2     # symmetric passive
    CLIENT 		= 3     # client
    SERVER 		= 4     # server
    BROADCAST 		= 5     # broadcast
    CONTROL 		= 6     # NTP control message
    PRIVATE		= 7     # reserved for private use

class Stratum(enum.IntEnum):
    # _ignore_ = [ 'i' ]
    UNSPECIFIED		= 0     # unspecified or invalid
    PRIMARY             = 1     # primary server (e.g., with a GPS receiver)

    @classmethod
    def SECONDARY(cls, i):
        assert i >= 2 and i <= 15
        return cls(i)

    _enum_range(locals(), 'SECONDARY', 2, 15+1)

    UNSYNCHRONIZED	= 16    # unsynchronized

    @classmethod
    def RESERVED(cls, i):
        assert i >= 17 and i <= 255
        return cls(i)

    _enum_range(locals(), 'RESERVED', 17, 255+1)

ReferenceIds = {
    # Reference IDs from RFC5905
    'GOES' : 'Geosynchronous Orbit Environment Satellite',
    'GPS'  : 'Global Position System',
    'GAL'  : 'Galileo Positioning System',
    'PPS'  : 'Generic pulse-per-second',
    'IRIG' : 'InterRange Instrumentation Group',
    'WWVB' : 'LF Radio WWVB Ft. Collins, CO 60 kHz',
    'DCF'  : 'LF Radio DCF77 Mainflingen, DE 77.5 kHz',
    'HBG'  : 'LF Radio HBG Prangins, HB 75 kHz',
    'MSF'  : 'LF Radio MSF Anthorn, UK 60 kHz',
    'JJY'  : 'LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz',
    'LORC' : 'MF Radio LORAN C station, 100 kHz',
    'TDF'  : 'MF Radio Allouis, FR 162 kHz',
    'CHU'  : 'HF Radio CHU Ottawa, Ontario',
    'WWV'  : 'HF Radio WWV Ft. Collins, CO',
    'WWVH' : 'HF Radio WWVH Kauai, HI',
    'NIST' : 'NIST telephone modem',
    'ACTS' : 'NIST telephone modem',
    'USNO' : 'USNO telephone modem',
    'PTB'  : 'European telephone modem',
    }

KissCodes = {
    'ACST' : 'The association belongs to a unicast server.',
    'AUTH' : 'Server authentication failed.',
    'AUTO' : 'Autokey sequence failed.',
    'BCST' : 'The association belongs to a broadcast server.',
    'CRYP' : 'Cryptographic authentication or identification failed.',
    'DENY' : 'Access denied by remote server.',
    'DROP' : 'Lost peer in symmetric mode.',
    'RSTR' : 'Access denied due to local policy.',
    'INIT' : 'The association has not yet synchronized for the first time.',
    'MCST' : 'The association belongs to a dynamically discovered server.',
    'NKEY' : 'No key found. Either the key was never installed or is not trusted.',
    'RATE' : 'Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold.',
    'RMOT' : 'Alteration of association from a remote host running ntpdc.',
    'STEP' : 'A step change in system time has occurred, but the association has not yet resynchronized.',
    }

# Preliminary for NTS draft-15

NTS_ALPN_PROTO = 'ntske/1'

NTS_TLS_Key_Label = b'EXPORTER-network-time-security'
NTS_TLS_Key_Label_Legacy = b'EXPORTER-network-time-security/1'
if 0:
    # A bug in OpenSSL 1.1.1 stops it from handling long export labels
    # https://mailarchive.ietf.org/arch/msg/ntp/nkc-9n6XOPt5Glgi_ueLvuD9EfY
    # Work around this by using a shorter string for the moment.
    # Note that this change must be made in both server and client.
    NTS_TLS_Key_Label = NTS_TLS_Key_Label_Workaround

NTS_TLS_Key_LEN = 32
NTS_TLS_Key_C2S = b'\0\0\0\x0f\x00'
NTS_TLS_Key_S2C = b'\0\0\0\x0f\x01'

NTPV4_DEFAULT_PORT = 123

@enum.unique
class NTPExtensionFieldType(enum.IntEnum):
    Unique_Identifier = 0x0104
    NTS_Cookie = 0x0204
    NTS_Cookie_Placeholder = 0x0304
    NTS_Authenticator = 0x0404
