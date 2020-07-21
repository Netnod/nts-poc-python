from cffi import FFI

_ffi = FFI()

_ffi.cdef('''
  typedef struct AES_SIV_CTX_st AES_SIV_CTX;

  AES_SIV_CTX* AES_SIV_CTX_new();
  int AES_SIV_CTX_copy(AES_SIV_CTX *dst, AES_SIV_CTX const* src);
  void AES_SIV_CTX_cleanup(AES_SIV_CTX *ctx);
  void AES_SIV_CTX_free(AES_SIV_CTX *ctx);

  int AES_SIV_Init(AES_SIV_CTX *ctx, unsigned char const *key, size_t key_len);
  int AES_SIV_AssociateData(AES_SIV_CTX *ctx, unsigned char const *data,
                            size_t len);
  int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx, unsigned char *v_out,
                           unsigned char *c_out, unsigned char const *plaintext,
                           size_t len);
  int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, unsigned char *out,
                           unsigned char const *v, unsigned char const *c,
                           size_t len);

  int AES_SIV_Encrypt(AES_SIV_CTX *ctx,
                      unsigned char *out, size_t *out_len,
                      unsigned char const* key, size_t key_len,
                      unsigned char const* nonce, size_t nonce_len,
                      unsigned char const* plaintext, size_t plaintext_len,
                      unsigned char const* ad, size_t ad_len);

  int AES_SIV_Decrypt(AES_SIV_CTX *ctx,
                      unsigned char *out, size_t *out_len,
                      unsigned char const* key, size_t key_len,
                      unsigned char const* nonce, size_t nonce_len,
                      unsigned char const* ciphertext, size_t ciphertext_len,
                      unsigned char const* ad, size_t ad_len);
''')

_libaes_siv = _ffi.dlopen("./libaes_siv/libaes_siv.so")

class AES_SIV:
    def __init__(self, other=None):
        self._ctx = _libaes_siv.AES_SIV_CTX_new()
        self._libaes_siv = _libaes_siv
        if self._ctx == _ffi.NULL:
            raise IOError("AES_SIV_CTX_new")
        if other is not None:
            assert isinstance(other, AES_SIV)
            if _libaes_siv.AES_SIV_CTX_copy(self._ctx, other._ctx) != 1:
                raise IOError("AES_SIV_CTX_copy")

    def __del__(self):
        self._libaes_siv.AES_SIV_CTX_free(self._ctx)

    def encrypt(self, key, nonce, plaintext, ad):
        key_ptr = _ffi.cast("unsigned char const*", _ffi.from_buffer(key))
        key_len = len(key)
        if nonce is None:
            nonce_ptr = _ffi.cast("unsigned char const*", _ffi.NULL)
            nonce_len = 0
        else:
            nonce_ptr = _ffi.cast("unsigned char const*", _ffi.from_buffer(nonce))
            nonce_len = len(nonce)
        plaintext_ptr = _ffi.cast("unsigned char const*", _ffi.from_buffer(plaintext))
        plaintext_len = len(plaintext)
        if ad is None:
            ad_ptr = _ffi.NULL
            ad_len = 0
        else:
            ad_ptr = _ffi.cast("unsigned char const*", _ffi.from_buffer(ad))
            ad_len = len(ad)

        out = bytearray(plaintext_len + 16)
        out_ptr = _ffi.cast("unsigned char*",  _ffi.from_buffer(out))
        out_len = _ffi.new("size_t[1]")
        out_len[0] = plaintext_len + 16

        ret = _libaes_siv.AES_SIV_Encrypt(
            self._ctx,
            out_ptr, out_len,
            key_ptr, key_len,
            nonce_ptr, nonce_len,
            plaintext_ptr, plaintext_len,
            ad_ptr, ad_len)
        
        if ret != 1:
            raise IOError("AES_SIV_Encrypt")
        return out

    def decrypt(self, key, nonce, ciphertext, ad):
        if len(ciphertext) < 16:
            return None
        
        key_ptr = _ffi.cast("unsigned char const*", _ffi.from_buffer(key))
        key_len = len(key)
        if nonce is None:
            nonce_ptr = _ffi.cast("unsigned char const*", _ffi.NULL)
            nonce_len = 0
        else:
            nonce_ptr = _ffi.cast("unsigned char const*", _ffi.from_buffer(nonce))
            nonce_len = len(nonce)
        ciphertext_ptr = _ffi.cast("unsigned char const*", _ffi.from_buffer(ciphertext))
        ciphertext_len = len(ciphertext)
        if ad is None:
            ad_ptr = _ffi.NULL
            ad_len = 0
        else:
            ad_ptr = _ffi.cast("unsigned char const*", _ffi.from_buffer(ad))
            ad_len = len(ad)

        out = bytearray(ciphertext_len - 16)
        out_ptr = _ffi.cast("unsigned char*", _ffi.from_buffer(out))
        out_len = _ffi.new("size_t[1]")
        out_len[0] = ciphertext_len - 16

        ret = _libaes_siv.AES_SIV_Decrypt(self._ctx,
                                          out_ptr, out_len,
                                          key_ptr, key_len,
                                          nonce_ptr, nonce_len,
                                          ciphertext_ptr, ciphertext_len,
                                          ad_ptr, ad_len)

        if ret != 1:
            return None
        return out

