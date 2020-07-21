#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import os
import stat
import binascii
import struct
from threading import  Timer

try:
    import configparser
except ImportError:
    import ConfigParser as configparser
try:
    from io import StringIO
except ImportError:
    from cStringIO import StringIO
from constants import *

"""

The master key handling is really simplistic right now.
It's slow and dumb, but it works and is easy to debug.

add_master_key will create a new key called "keyid.key" in the
master_keys directory, it then calls refresh_master_keys.

refresh_master_keys will scan the master_keys directory and sort the
key files by modification time.  If there are more than
MAX_MASTER_KEYS files in the directory the oldest ones will be
removed, and the rest of the keys will be loaded.

get_master_keys calls refresh_master_key and returns a list of
(keyid, key) tuples sorted by modification time.

get_master_key gets the most recent master (keyid, key) tuple.

A future version could use a thread which uses inotify to be notified
if any of the keys have changed so that it doesn't have to reread all
the keys every time the keys are used.

"""

KEY_ID_LEN = 4
KEY_LEN = 32

CONFIG_DEFAULTS = '''
[ntske]
syslog =
port = 443

[ntpv4]
server =
port = 123

[keys]
key_label =
master_keys_dir = master_keys

[mgmt]
host =
port =
'''

class ServerHelper(object):
    MAX_MASTER_KEYS = 3

    def __init__(self, config_path = 'server.ini'):
        config = configparser.RawConfigParser(
            allow_no_value = True)
        config.readfp(StringIO(CONFIG_DEFAULTS))
        config.read(config_path)

        if 1:
            import sys
            config.write(sys.stdout)

        self.syslog            = config.get('ntske', 'syslog')
        self.ntske_port        = config.get('ntske', 'port')
        self.ntske_server_cert = config.get('ntske', 'server_cert')
        self.ntske_server_key  = config.get('ntske', 'server_key')

        self.ntpv4_server      = config.get('ntpv4', 'server')
        if self.ntpv4_server:
            self.ntpv4_server = self.ntpv4_server.encode('ASCII')
        else:
            self.ntpv4_server = None
        self.ntpv4_port        = config.get('ntpv4', 'port')
        if self.ntpv4_port:
            self.ntpv4_port = int(self.ntpv4_port)
        else:
            self.ntpv4_port = None

        self.master_keys_dir   = config.get('keys', 'master_keys_dir')
        self.key_label         = config.get('keys', 'key_label')
        if self.key_label:
            self.key_label = self.key_label.encode('ASCII')
        else:
            self.key_label = NTS_TLS_Key_Label

        if not os.path.isdir(self.master_keys_dir):
            os.makedirs(self.master_keys_dir)

        self.mgmt_host         = config.get('mgmt', 'host')
        self.mgmt_port         = config.get('mgmt', 'port')
        if self.mgmt_port:
            self.mgmt_port = int(self.mgmt_port)
        else:
            self.mgmt_port = None

    def add_master_key(self):
        while 1:
            keyid = os.urandom(KEY_ID_LEN)
            path = os.path.join(self.master_keys_dir, '%s.key' %
                                binascii.hexlify(keyid).decode('ascii'))

            # We could actually get a keyid collision, retry if that happens
            if not os.path.exists(path):
                break

        key = os.urandom(KEY_LEN)

        with open(path + '+', 'w') as f:
            f.write('%s\n' % binascii.hexlify(key).decode('ascii'))
        os.rename(path + '+', path)

        return key

    def refresh_master_keys(self):
        try:
            self.load_master_keys()
        except Exception:
            traceback.print_exc()
        finally:
            t = Timer(60, self.refresh_master_keys)
            t.daemon = True
            t.start()

    def load_master_keys(self):
        a = []
        for fn in os.listdir(self.master_keys_dir):
            if fn.endswith('.key'):
                if len(fn) == 8:
                    keyid = binascii.unhexlify(fn[:-4])
                else:
                    keyid = struct.pack('>L', int(fn[:-4], 16))
                path = os.path.join(self.master_keys_dir, fn)
                st = os.stat(path)
                a.append((st[stat.ST_MTIME], keyid, path))

        a.sort()

        # Delete all but the last three keys
        while len(a) > self.MAX_MASTER_KEYS:
            try:
                os.unlink(a[0][2])
            except IOError:
                pass
            del a[0]

        keys = []
        for mtime, keyid, path in a:
            keyvalue = bytes(binascii.unhexlify(open(path).read().strip()))
            keys.append((keyid, keyvalue))

        if 1:
            print("pid %u master keys [ %s ]" % (
                os.getpid(),
                ', '.join(
                    [ str("%s" % (
                        binascii.hexlify(k))) for k, v in keys ])))

        if not keys:
            keys.append(self.add_master_key())

        self._master_keys = keys

    def get_master_keys(self):
        return self._master_keys

    def get_master_key(self):
        return self.get_master_keys()[-1]

if __name__ == '__main__':
    sh = ServerHelper()
    sh.add_master_key()
