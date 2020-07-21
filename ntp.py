#! /usr/bin/python
from __future__ import division, print_function, unicode_literals

import struct
import time
import math
import binascii

from constants import *
from util import *

class NTPExtensionField(object):
    def __init__(self, field_type, value):
        assert field_type >= 0 and field_type <= 65535
        self.field_type = field_type
        self.value = value
        self.force_size = None

    @staticmethod
    def peek(buf, offset = 0):
        field_type, field_len = struct.unpack_from('>HH', buf, offset)
        if field_len % 4 != 0:
            raise ValueError("field length is not a multiple of 4")
        if offset + field_len > len(buf):
            raise ValueError("field extends past end of buffer")
        return field_type, field_len

    def pack(self, last = False):
        if self.force_size is True:
            field_len = 4 + len(self.value)
        elif self.force_size:
            field_len = self.force_size
        else:
            field_len = 4 + len(self.value)  # Header and value
            field_len = (field_len + 3) & ~3   # Round length up to word
            if last:           # Enforce minimum extension field size
                # the last extension field MUST be >28 octets including header
                field_len = max(field_len, 28)
            else:
                # other extension fields MUST be >16 octets including header
                field_len = max(field_len, 16)

        padding = bytes(bytearray(field_len - len(self.value) - 4))

        a = [
            struct.pack('>HH', self.field_type, field_len),
            self.value, padding ]

        b = b''.join(a)

        return b

class NTPPacket(object):
    HEADER_FMT = '>BBBbLL4sQQQQ'

    # Default values based on recommended client values from
    # https://tools.ietf.org/html/draft-ietf-ntp-data-minimization-03
    def __init__(self,
                 li = LeapIndicator.NORMAL,
                 vn = 4,
                 mode = Mode.CLIENT,
                 stratum = Stratum.UNSPECIFIED,
                 poll = 0,
                 precision = 0x20,
                 root_delay = 0,
                 root_dispersion = 0,
                 reference_id = b'',
                 reference_timestamp = 0,
                 origin_timestamp = 0,
                 receive_timestamp = 0,
                 transmit_timestamp = 0,
                 ext = None,
                 keyid = None,
                 mac = None,
                 ):
        self.li = LeapIndicator(li)
        self.vn = vn
        self.mode = Mode(mode)
        self.stratum = Stratum(stratum)
        self.poll = poll
        self.precision = precision
        self.root_delay = root_delay
        self.root_dispersion = root_dispersion
        self.reference_id = reference_id
        self.reference_timestamp = reference_timestamp
        self.origin_timestamp = origin_timestamp
        self.receive_timestamp = receive_timestamp
        self.transmit_timestamp = transmit_timestamp
        if ext is not None:
            self.ext = ext
        else:
            self.ext = []
        self.keyid = keyid
        self.mac = mac

        self.debug = 0

    def pack(self):
        flags = ((self.li << 6) |
                 (self.vn << 3) |
                 (self.mode << 0))

        a = []

        a.append(struct.pack(
            self.HEADER_FMT,
            flags,
            self.stratum,
            self.poll,
            self.precision,
            self.root_delay,
            self.root_dispersion,
            bytes(self.reference_id),
            self.reference_timestamp,
            self.origin_timestamp,
            self.receive_timestamp,
            self.transmit_timestamp,))

        for i in range(len(self.ext)):
            a.append(self.ext[i].pack(i == len(self.ext) - 1))

        if self.keyid != None:
            a.append(struct.pack('>L', self.keyid))
            a.append(self.mac)

        return bytes(b''.join(a))

    def __repr__(self):
        if self.stratum == Stratum.PRIMARY:
            reference_id = bytes(self.reference_id).rstrip(b'\0')
            reference_explanation = ReferenceIds.get(reference_id)
        else:
            reference_id = bytes(self.reference_id)
            assert len(reference_id) <= 4
            while len(reference_id) < 4:
                reference_id += b'\0'
            t = tuple(bytearray(reference_id).__iter__())
            reference_explanation = '%u.%u.%u.%u' % t
        if reference_explanation:
            reference_explanation = " # " + reference_explanation
        else:
            reference_explanation = ""

        a = [
            "li                  = %20u # %s" % (self.li, self.li),
            "vn                  = %20s" % (self.vn),
            "mode                = %20u # %s" % (self.mode, self.mode),
            "stratum             = %20u # %s" % (self.stratum, self.stratum),
            "poll                = %20u # %s s" % (self.poll, 2**self.poll),
            "precision           = %20d # %.3g s" % (
            self.precision, 2**self.precision),
            "root_delay          = %20u # %.3g s" % (
            self.root_delay, ntp_short_to_seconds(self.root_delay)),
            "root_dispersion     = %20u # %.3g s" % (
            self.root_dispersion, ntp_short_to_seconds(self.root_dispersion)),
            "reference_id        = %20s%s" % (
            repr(reference_id), reference_explanation),
            "reference_timestamp = %20u # %s" % (
            self.reference_timestamp,
            ntp_ts_to_iso(self.reference_timestamp)),
            "origin_timestamp    = %20u # %s" % (
            self.origin_timestamp,
            ntp_ts_to_iso(self.origin_timestamp)),
            "receive_timestamp   = %20u # %s" % (
            self.receive_timestamp,
            ntp_ts_to_iso(self.receive_timestamp)),
            "transmit_timestamp  = %20u # %s" % (
            self.transmit_timestamp,
            ntp_ts_to_iso(self.transmit_timestamp)),
            ]

        if self.ext:
            a.append("ext                 = [ # %u fields" % len(self.ext))
            for ext in self.ext:
                try:
                    t = NTPExtensionFieldType(ext.field_type)
                except ValueError:
                    t = '0x%04x' % ext.field_type
                a.append("  NTPExtensionField(%s, unhexlify('''%s'''))," % (
                        t, hexlify(ext.value[:10])))
            a.append("                      ]")

        if hasattr(self, 'enc_ext') and self.enc_ext is not None:
            a.append("enc_ext             = [ # %u fields" % len(self.enc_ext))
            for ext in self.enc_ext:
                try:
                    t = NTPExtensionFieldType(ext.field_type)
                except ValueError:
                    t = '0x%04x' % ext.field_type
                a.append("  NTPExtensionField(%s, unhexlify('''%s'''))," % (
                        t, hexlify(ext.value)))
            a.append("                      ]")

        if self.keyid is not None:
            a.append("keyid               = %08x" % self.keyid)
            a.append("mac                 = %s" % binascii.hexlify(self.mac))

        return '\n'.join(a)

    def handle_field(self, field, buf, offset):
        self.ext.append(field)

    @classmethod
    def unpack(cls, buf, **kwargs):
        offset = 0
        (flags, stratum, poll, precision,
         root_delay, root_dispersion, reference_id,
         reference_timestamp,
         origin_timestamp,
         receive_timestamp,
         transmit_timestamp) = struct.unpack_from(
            cls.HEADER_FMT, buf, offset)
        offset += struct.calcsize(cls.HEADER_FMT)

        stratum = Stratum(stratum)

        if len(buf) % 4 != 0:
            raise ValueError("buffer size is not a multiple of 4")

        remain = len(buf) - offset

        packet = cls(
            li = LeapIndicator((flags >> 6) & 3),
            vn = (flags >> 3) & 7,
            mode = Mode((flags >> 0) & 7),
            stratum = stratum,
            poll = poll,
            precision = precision,
            root_delay = root_delay,
            root_dispersion = root_dispersion,
            reference_id = reference_id,
            reference_timestamp = reference_timestamp,
            origin_timestamp = origin_timestamp,
            receive_timestamp = receive_timestamp,
            transmit_timestamp = transmit_timestamp,
            **kwargs)

        while remain >= 28:
            field_type, field_len = NTPExtensionField.peek(buf, offset)

            if field_len < 4:
                raise ValueEror("field is too short")
            if field_len % 4 != 0:
                raise ValueError("field length is not a multiple of 4")

            field = NTPExtensionField(field_type,
                                      buf[offset + 4 : offset + field_len])

            packet.handle_field(field, buf, offset)

            remain -= field_len
            offset += field_len

        keyid = None
        mac = None

        if remain in [ 4, 20, 24 ]:
            packet.keyid = struct.unpack_from('>L', buf, offset)[0]
            packet.mac = buf[offset+4:]

            if len(packet.mac) == 0:
                print("Crypto NAK %08x" % packet.keyid)
                assert packet.keyid == 0

            offset += remain
            remain = 0

        elif remain:
            raise ValueError("garbage at end of NTP packet")

        return packet
