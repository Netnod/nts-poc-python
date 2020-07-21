#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import aes_siv
import binascii
import sys

def unhexlify(s):
    return binascii.unhexlify(''.join(s.strip().split()))

def hexlify(d):
    return ' '.join([ binascii.hexlify(d[i:i+4]).decode('ASCII')
                      for i in range(0, len(d), 4) ])

aead = aes_siv.AES_SIV()

def test_encrypt():
    print("Key:  ", hexlify(key), "(%d bytes)" % len(key))
    if nonce is None:
        print("Nonce:", None)
    else:
        print("Nonce:", hexlify(nonce), "(%d bytes)" % len(nonce))
    if ad is None:
        print("AD:   ", None)
    else:
        print("AD:   ", hexlify(ad), "(%d bytes)" % len(ad))
    print("Plain:", hexlify(plaintext), "(%d bytes)" % len(plaintext))
    print()

    ciphertext = aead.encrypt(key, nonce, plaintext, ad)

    print()
    print("Out:   ", hexlify(ciphertext), "(%d bytes)" % len(ciphertext))
    print()

def test_decrypt():
    print("Key:  ", hexlify(key), "(%d bytes)" % len(key))
    if nonce is None:
        print("Nonce:", None)
    else:
        print("Nonce:", hexlify(nonce), "(%d bytes)" % len(nonce))
    if ad is None:
        print("AD:   ", None)
    else:
        print("AD:   ", hexlify(ad), "(%d bytes)" % len(ad))
    print("Enc:  ", hexlify(ciphertext), "(%d bytes)" % len(ciphertext))
    print()

    plaintext = aead.decrypt(key, nonce, ciphertext, ad)
    if plaintext is None:
        print("Decryption failed")
        sys.exit(1)

    print("Out:   ", hexlify(plaintext), "(%d bytes)" % len(plaintext))
    print()

    return plaintext

print("Test data based on A.2 in https://tools.ietf.org/html/rfc5297")
print()

if 1:
    print("AD2 has been dropped")
    print()

    key = unhexlify('''7f7e7d7c 7b7a7978 77767574 73727170
                       40414243 44454647 48494a4b 4c4d4e4f''')

    ad = unhexlify('''00112233 44556677 8899aabb ccddeeff
                      deaddada deaddada ffeeddcc bbaa9988
                      77665544 33221100''')
    nonce = unhexlify('''09f91102 9d74e35b d84156c5 635688c0''')

    plaintext = unhexlify('''74686973 20697320 736f6d65 20706c61
                             696e7465 78742074 6f20656e 63727970
                             74207573 696e6720 5349562d 414553''')

    test_encrypt()

    # Test data from A.2 with zero length plaintext

    key = unhexlify('''7f7e7d7c 7b7a7978 77767574 73727170
                       40414243 44454647 48494a4b 4c4d4e4f''')

    ad = unhexlify('''00112233 44556677 8899aabb ccddeeff
                      deaddada deaddada ffeeddcc bbaa9988
                      77665544 33221100''')
    nonce = unhexlify('''09f91102 9d74e35b d84156c5 635688c0''')

    plaintext = unhexlify('''''')

    print("AD2 has been dropped, zero length plaintext")
    print()

    test_encrypt()

    key = unhexlify('''00010203 04050607 08090a0b 0c0d0e0f
                       10111213 14151617 18191a1b 1c1d1e1f''')

    ad = unhexlify('''''')

    nonce = unhexlify('''20212223 24252627 28292a2b 2c2d2e2f''')

    plaintext = unhexlify('''30313233 34353637 38393a3b 3c3d3e3f''')

    print("Zero length AD")
    print()

    test_encrypt()

    if 1:
        ad = None

        print("No AD")
        print()

        test_encrypt()

if 1:
    key = unhexlify('''7f7e7d7c 7b7a7978 77767574 73727170
                       40414243 44454647 48494a4b 4c4d4e4f''')

    ad = unhexlify('''00112233 44556677 8899aabb ccddeeff
                      deaddada deaddada ffeeddcc bbaa9988
                      77665544 33221100''')

    nonce = unhexlify('''09f91102 9d74e35b d84156c5 635688c0''')

    plaintext = unhexlify('''74686973 20697320 736f6d65 20706c61
                             696e7465 78742074 6f20656e 63727970
                             74207573 696e6720 5349562d 414553''')

    print("Decrypt")
    print()

    test_encrypt()

if 1:
    print("Decrypt cookie")
    print()

    key = unhexlify('''3fc91575cf885a02820a019e846fa2a68c9aa6543f4c1ebabea74ca0d16aeda8''')

    ad = None

    nonce = unhexlify('''cd65766f2c8fb4cc6b8d5b7aca60c5ec''')

    ciphertext = unhexlify('''a507af99a998d8395e045f75ffa2be8c3b025e7b46a4f2472777e251e4fc36b7ed1287f362cd54b1152488c5873a6fc70ec582beb3640aaae23038c694939e8d71c51d88f6a6def90efc99906cd3c2cb''')

    test_decrypt()

if 0:
    print("Decrypt cookie")
    print()

    key = unhexlify('''3fc91575cf885a02820a019e846fa2a68c9aa6543f4c1ebabea74ca0d16aeda8''')

    ad = None

    nonce = unhexlify('''cd65766f2c8fb4cc6b8d5b7aca60c5ec''')

    ciphertext = unhexlify('''a507af99a998d8395e045f75ffa2be8c3b025e7b46a4f2472777e251e4fc36b7ed1287f362cd54b1152488c5873a6fc70ec582beb3640aaae23038c694939e8d71c51d88f6a6def90efc99906cd3c2cb''')

    test_decrypt()

    ad = b''
    test_decrypt()

if 1:
    print("Decrypt")
    print()

    key = unhexlify('''fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff''')

    ad = None

    nonce = unhexlify('''10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627''')

    ciphertext = unhexlify('''85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c''')

    test_decrypt()

if 1:
    key = unhexlify('''fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff''')

    ad = unhexlify('''10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627''')

    nonce = unhexlify('')
    nonce = None

    ciphertext = unhexlify('''85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c''')

    print("Decrypt")
    print()

    test_decrypt()

if 1:
    key        = unhexlify('''2be26209 fdc335d0 13aeb45a ecd91f1a

                          a4e1055b 8f7fdae8 c592b87d 09200b74''')

    nonce      = unhexlify('''7208a18a 82f9a600 130d32d0 5c9d74dd''')

    ad         = unhexlify('''23000020 00000000 00000000 00000000

                          00000000 00000000 00000000 00000000

                          00000000 00000000 40478317 6d76ee40

                          01040024 62733aee 2f65b707 8698f4f1

                          b42cf4f8 bb7149ed d0b8a6d2 426a823c

                          a6563ff5 02040068 ea0e3f0d 06043007

                          46b5d7c0 9f9e2a29 a785c2b9 b6d49397

                          1faefc47 977295e2 127b7dfd dcfa59ed

                          82e24e32 94789bb2 0d7dddf8 a5c7d998

                          2ce752f0 775ab86e 985a57f2 d34cac37

                          d6621199 d600a4fd af6de2b8 a70bfdd6

                          1b072c09 10d5e57a 1956a84c''')

    ciphertext = unhexlify('''464470e5 98f324b7 31647dde 6191623e''')

    plain  = unhexlify('''''')

    print("Decrypt auth")
    print()

    r = test_decrypt()
    assert r == plain
