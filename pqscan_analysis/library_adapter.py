"""OpenSSL EVP adapter; only loaded in the isolated artifact-test container."""
import ctypes as C
import hashlib
from pathlib import Path


class Param(C.Structure):
    _fields_ = [('key', C.c_char_p), ('data_type', C.c_uint), ('data', C.c_void_p),
                ('data_size', C.c_size_t), ('return_size', C.c_size_t)]


def octets(key, value):
    buffer = C.create_string_buffer(value)
    params = (Param * 2)()
    params[0] = Param(key, 5, C.cast(buffer, C.c_void_p), len(value), 0)
    return params, buffer


class Adapter:
    def __init__(self, path):
        self.path = str(Path(path).resolve())
        self.lib = C.CDLL(self.path, mode=C.RTLD_LOCAL)
        signatures = {
            'OSSL_LIB_CTX_new': (C.c_void_p, []), 'OSSL_LIB_CTX_free': (None, [C.c_void_p]),
            'OSSL_PROVIDER_load': (C.c_void_p, [C.c_void_p, C.c_char_p]),
            'OSSL_PROVIDER_get0_name': (C.c_char_p, [C.c_void_p]),
            'OSSL_PROVIDER_unload': (C.c_int, [C.c_void_p]),
            'OpenSSL_version': (C.c_char_p, [C.c_int]),
            'EVP_PKEY_CTX_new_from_name': (C.c_void_p, [C.c_void_p, C.c_char_p, C.c_char_p]),
            'EVP_PKEY_CTX_new_from_pkey': (C.c_void_p, [C.c_void_p, C.c_void_p, C.c_char_p]),
            'EVP_PKEY_fromdata_init': (C.c_int, [C.c_void_p]),
            'EVP_PKEY_fromdata': (C.c_int, [C.c_void_p, C.POINTER(C.c_void_p), C.c_int, C.POINTER(Param)]),
            'EVP_PKEY_get0_provider': (C.c_void_p, [C.c_void_p]),
            'EVP_PKEY_CTX_free': (None, [C.c_void_p]), 'EVP_PKEY_free': (None, [C.c_void_p]),
            'EVP_PKEY_decapsulate_init': (C.c_int, [C.c_void_p, C.POINTER(Param)]),
            'EVP_PKEY_decapsulate': (C.c_int, [C.c_void_p, C.c_void_p, C.POINTER(C.c_size_t), C.c_char_p, C.c_size_t]),
            'EVP_MD_CTX_new': (C.c_void_p, []), 'EVP_MD_CTX_free': (None, [C.c_void_p]),
            'EVP_DigestVerifyInit_ex': (C.c_int, [C.c_void_p, C.c_void_p, C.c_char_p, C.c_void_p, C.c_char_p, C.c_void_p, C.POINTER(Param)]),
            'EVP_DigestVerify': (C.c_int, [C.c_void_p, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t]),
            'ERR_clear_error': (None, []),
        }
        for name, (restype, args) in signatures.items():
            function = getattr(self.lib, name); function.restype = restype; function.argtypes = args
        self.ctx = self.lib.OSSL_LIB_CTX_new()
        if not self.ctx: raise RuntimeError('Cannot create library context')
        self.provider = self.lib.OSSL_PROVIDER_load(self.ctx, b'default')
        if not self.provider or self.lib.OSSL_PROVIDER_get0_name(self.provider) != b'default':
            raise RuntimeError('Built-in default provider unavailable')
        self.properties = b'provider=default'

    def import_key(self, algorithm, value, private):
        ctx = self.lib.EVP_PKEY_CTX_new_from_name(self.ctx, algorithm, self.properties)
        key = C.c_void_p()
        params, keep = octets(b'priv' if private else b'pub', value)
        try:
            if not ctx or self.lib.EVP_PKEY_fromdata_init(ctx) != 1: raise RuntimeError('EVP key import setup failed')
            if self.lib.EVP_PKEY_fromdata(ctx, C.byref(key), 0x87 if private else 0x86, params) != 1:
                raise ValueError('EVP rejected key encoding')
            if self.lib.EVP_PKEY_get0_provider(key) != self.provider:
                self.lib.EVP_PKEY_free(key); raise RuntimeError('Unexpected key provider')
            return key
        finally: self.lib.EVP_PKEY_CTX_free(ctx)

    def decapsulate(self, dk, ciphertext):
        key = self.import_key(b'ML-KEM-768', dk, True)
        ctx = self.lib.EVP_PKEY_CTX_new_from_pkey(self.ctx, key, self.properties)
        output, size = C.create_string_buffer(32), C.c_size_t(32)
        try:
            if not ctx or self.lib.EVP_PKEY_decapsulate_init(ctx, None) != 1: raise RuntimeError('EVP decapsulation setup failed')
            if self.lib.EVP_PKEY_decapsulate(ctx, output, C.byref(size), ciphertext, len(ciphertext)) != 1:
                raise ValueError('EVP rejected decapsulation input')
            if size.value != 32: raise RuntimeError('Unexpected shared-secret size')
            return output.raw
        finally:
            self.lib.EVP_PKEY_CTX_free(ctx); self.lib.EVP_PKEY_free(key); self.lib.ERR_clear_error()

    def verify_context(self, pk, message, context, signature):
        key = self.import_key(b'ML-DSA-65', pk, False)
        ctx = self.lib.EVP_MD_CTX_new()
        params, keep = octets(b'context-string', context)
        try:
            if not ctx: raise RuntimeError('EVP verify allocation failed')
            if self.lib.EVP_DigestVerifyInit_ex(ctx, None, None, self.ctx, self.properties, key, params) != 1:
                if len(context) > 255: return False
                raise RuntimeError('EVP verification setup failed')
            result = self.lib.EVP_DigestVerify(ctx, signature, len(signature), message, len(message))
            if result not in (0, 1): raise RuntimeError('EVP verification operation failed')
            return result == 1
        finally:
            self.lib.EVP_MD_CTX_free(ctx); self.lib.EVP_PKEY_free(key); self.lib.ERR_clear_error()

    def metadata(self):
        maps = Path('/proc/self/maps').read_text().splitlines()
        paths = sorted({line.split()[-1] for line in maps if 'libcrypto.so' in line})
        if paths != [self.path]: raise RuntimeError('Loaded libcrypto does not match the staged artifact')
        return {'version': self.lib.OpenSSL_version(0).decode(), 'provider': 'default',
                'loaded_path': self.path, 'loaded_sha256': hashlib.sha256(Path(self.path).read_bytes()).hexdigest()}

    def close(self):
        self.lib.OSSL_PROVIDER_unload(self.provider); self.lib.OSSL_LIB_CTX_free(self.ctx)
