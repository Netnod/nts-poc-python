#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import socket
import os
import time
import traceback
import binascii
import stat
import sys

from util import epoch_to_ntp_ts
from server_helper import ServerHelper
from constants import *
from ntp import NTPExtensionField,  NTPExtensionFieldType
from nts import NTSServerPacketHelper, NTSCookie

assert sys.version_info[0] == 3

def handle(req, master_key):
    ts = epoch_to_ntp_ts(time.time())

    resp = NTSServerPacketHelper(
        mode = Mode.SERVER,
        stratum = 5,
        reference_id = b'\0\0\0\0',
        precision = -10,
        reference_timestamp = ts,
        origin_timestamp = req.transmit_timestamp,
        receive_timestamp = ts,
        transmit_timestamp = ts,
        )

    if req.unique_identifier is not None:
        resp.ext.append(NTPExtensionField(
            NTPExtensionFieldType.Unique_Identifier,
            req.unique_identifier))

    if req.enc_ext is not None:
        if req.unique_identifier is None:
            raise ValueError("unique identifier missing")

        resp.pack_key = req.pack_key
        resp.enc_ext = []

        keyid, key = master_key

        if req.nr_cookie_placeholders > 7:
            raise ValueError("too many cookie placeholders")

        for i in range(req.nr_cookie_placeholders + 1):
            cookie = NTSCookie().pack(
                keyid, key,
                req.aead_algo, req.pack_key, req.unpack_key)

            resp.enc_ext.append(NTPExtensionField(
                NTPExtensionFieldType.NTS_Cookie,
                cookie))

    return resp

def main():
    serverhelper = ServerHelper()
    serverhelper.refresh_master_keys()

    if serverhelper.ntpv4_server:
        host = serverhelper.ntpv4_server.strip()
    else:
        host = ''

    if serverhelper.ntpv4_port:
        port = int(serverhelper.ntpv4_port)
    else:
        port = NTPV4_DEFAULT_PORT

    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    sys.stdout.flush()

    while 1:
        try:
            data, addr = sock.recvfrom(65536)
        except socket.timeout:
            print("timeout")
            continue
        except KeyboardInterrupt:
            break
        except Exception:
            traceback.print_exc()

        print("RECV", repr(addr), len(data), repr(data[:10]))

        keys = serverhelper.get_master_keys()

        try:
            req = NTSServerPacketHelper.unpack(data, keys = dict(keys))
            print(req)
            print()

            resp = handle(req, master_key = keys[-1])
            buf = resp.pack()
            print("RESP", repr(addr), len(buf), repr(buf[:10]))
            print(resp)

            sock.sendto(buf, addr)
        except KeyboardInterrupt:
            break
        except Exception:
            traceback.print_exc()
            open("dump/dump-%s-%.3f.bin" % (addr[0], time.time()), 'wb').write(data)

        print()

        sys.stdout.flush()

if __name__ == '__main__':
    main()
