#! /usr/bin/python
from __future__ import division, print_function, unicode_literals

import socket
import sys
import os

def _default_verify_locations():
    for ca in [
        # Ubuntu: apt-get install ca-certificates
        '/etc/ssl/certs/ca-certificates.crt',
        # CentOS: yum install ca-certificates
        '/etc/pki/tls/cert.pem',
    ]:
        if os.path.exists(ca):
            return ca
    return None

class SSLWrapperException(Exception):
    pass

try:
    import ssl

    getattr(ssl.SSLSocket, 'export_keying_material')

    class BuiltinSSLWrapper(object):
        def _common(self, flags):
            self.ctx = ssl.SSLContext(flags)
            self.ctx.options |= (ssl.OP_NO_SSLv2 |
                                 ssl.OP_NO_SSLv3 |
                                 ssl.OP_NO_TLSv1 |
                                 ssl.OP_NO_TLSv1_1)

        def client(self, ca, disable_verify = None):
            self._common(ssl.PROTOCOL_TLS_CLIENT)
            if disable_verify:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE
            else:
                if ca is None:
                    self.ctx.load_default_certs()
                else:
                    self.ctx.load_verify_locations(ca)

        def server(self, cert, key):
            self._common(ssl.PROTOCOL_TLS_SERVER)

            self.ctx.load_cert_chain(cert, key)

        def connect(self, sock, hostname):
            sock.settimeout(1)
            s = self.ctx.wrap_socket(sock,
                                     server_hostname = hostname,
                                     suppress_ragged_eofs = False)
            return BuiltinSSLSocket(s)

        def accept(self, sock):
            try:
                s = self.ctx.wrap_socket(sock, server_side = True,
                                         suppress_ragged_eofs = False)
            except OSError:
                return None

            return BuiltinSSLSocket(s)

        def set_alpn_protocols(self, protocols):
            self.ctx.set_alpn_protocols(protocols)

    class BuiltinSSLSocket(object):
        def __init__(self, s):
            self.s = s

        def selected_alpn_protocol(self):
            return self.s.selected_alpn_protocol()

        def recv(self, n):
            try:
                return self.s.recv(n)
            except ssl.SSLEOFError as e:
                return None

        def sendall(self, buf):
            return self.s.sendall(buf)

        def export_keying_material(self, label, key_len, context):
            return self.s.export_keying_material(label, key_len, context)

        def shutdown(self):
            # Shutdown ought to work, but it doesn't, use unwrap instead
            # self.s.shutdown(socket.SHUT_RDWR)
            self.s = self.s.unwrap()

        def close(self):
            self.s.close()

        def info(self):
            cipher = self.s.cipher()
            return { 'tls_version' : cipher[1], 'cipher' : cipher[0] }

except AttributeError:
    pass

try:
    import OpenSSL

    getattr(OpenSSL.SSL.Connection, 'export_keying_material')

    class PyOpenSSLWrapper(object):
        CIPHERS = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            ]

        def _common(self):
            self.ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            self.ctx.set_options(OpenSSL.SSL.OP_NO_SSLv2 |
                                 OpenSSL.SSL.OP_NO_SSLv3 |
                                 OpenSSL.SSL.OP_NO_TLSv1 |
                                 OpenSSL.SSL.OP_NO_TLSv1_1)
            self.ctx.set_cipher_list(':'.join(self.CIPHERS).encode('ASCII'))

        def client(self, ca, disable_verify = False):
            self._common()

            if ca is None:
                ca = _default_verify_locations()
            if ca is not None:
                print("warning could not find root CA file")
            else:
                self.ctx.load_verify_locations(ca)

            if not disable_verify:
                self.ctx.set_verify(OpenSSL.SSL.VERIFY_PEER, self._verify_callback)

        def server(self, cert, key):
            self._common()

            self.ctx.use_certificate_file(cert)
            self.ctx.use_privatekey_file(key)

        def connect(self, sock, hostname):
            s = OpenSSL.SSL.Connection(self.ctx, sock)
            s.set_tlsext_host_name(hostname.encode("utf-8"))
            s.set_connect_state()
            self.verify_hostname = hostname
            return PyOpenSSLSocket(s)

        def accept(self, sock):
            s = OpenSSL.SSL.Connection(self.ctx, sock)
            s.set_accept_state()
            return PyOpenSSLSocket(s)

        def set_alpn_protocols(self, protocols):
            self.alpn_protocols = [ p.encode('ASCII') for p in protocols ]
            self.ctx.set_alpn_protos(self.alpn_protocols)

        def _alpn_cb(self, sock, protocols):
            for protocol in protocols:
                if protocol in self.alpn_protocols:
                    return protocol
            return None

        def _verify_callback(self, conn, cert, errno, depth, result):
            # TODO add support for Subject Alternate Name (SAN)
            subject = cert.get_subject()
            if result == 0:
                return False
            if depth == 0:
                for k, v in cert.get_subject().get_components():
                    k = k.decode('ASCII')
                    v = v.decode('ASCII')
                    if k == 'CN':
                        if v == self.verify_hostname:
                            return True
                        else:
                            print("hostname %s does not match CN %s in server certificate" % (
                                repr(self.verify_host), repr(v)), file = sys.stderr)
                    else:
                        print("unknown component %s %s in server certificate" % (repr(k), repr(v)))
                return False
            return True

    class PyOpenSSLSocket(object):
        def __init__(self, s):
            self.s = s
            self.s.do_handshake()

        def recv(self, n):
            try:
                return self.s.recv(n)
            except OpenSSL.SSL.ZeroReturnError:
                return b''
            except OpenSSL.SSL.SysCallError as e:
                if e.args[1] != 'Unexpected EOF':
                    raise
                raise SSLWrapperException(e)

        def sendall(self, buf):
            return self.s.sendall(buf)

        def export_keying_material(self, label, key_len, context):
            return self.s.export_keying_material(label, key_len, context)

        def shutdown(self):
            self.s.shutdown()

        def close(self):
            self.s.close()

        def selected_alpn_protocol(self):
           return self.s.get_alpn_proto_negotiated().decode('ASCII')

        def info(self):
            return {}

except ImportError:
    pass

except AttributeError:
    pass

if 'BuiltinSSLWrapper' in globals():
    # print("Using Python's builtin SSL implementation")
    SSLWrapper = BuiltinSSLWrapper
elif 'PyOpenSSLWrapper' in globals():
    # print("Using PyOpenSSL implementation")
    SSLWrapper = PyOpenSSLWrapper
else:
    raise RuntimeError("no usable SSL/TLS implementation found")

if __name__ == '__main__':
    sw = SSLWrapper()
    sw.connect('192.168.122.40', 4446, verify_host = 'zoo.weinigel.se')
