"""Reviewed adapter, imported only inside the validation container.

ML-KEM uses the pqcrypto Python API. ML-DSA context verification uses the
exported PQClean C entrypoint in the pinned wheel, not a fabricated Python API.
"""
import ctypes
import hashlib
from importlib import metadata
import os
from pathlib import Path
import platform


def initialize():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    # Docker Desktop kernels may expose dormant tunnel devices even with
    # --network=none. IFF_UP is the relevant distinction, not sysfs names alone.
    active = sorted(p.name for p in Path('/sys/class/net').iterdir()
                    if (p / 'flags').is_file() and int((p / 'flags').read_text().strip(), 16) & 1)
    isolation = {'uid': os.getuid(), 'active_interfaces': active,
                 'root_read_only': bool(os.statvfs('/').f_flag & os.ST_RDONLY),
                 'no_new_privileges': status['NoNewPrivs'].strip() == '1',
                 'capabilities_zero': int(status['CapEff'].strip(), 16) == 0,
                 'seccomp_filter': status['Seccomp'].strip() == '2'}
    if isolation != {'uid': 65534, 'active_interfaces': ['lo'], 'root_read_only': True,
                     'no_new_privileges': True, 'capabilities_zero': True, 'seccomp_filter': True}:
        raise RuntimeError('Container isolation preflight failed: ' + repr(isolation))
    versions = {name: metadata.version(name) for name in ('pqcrypto', 'cffi', 'pycparser')}
    if versions != {'pqcrypto': '0.3.4', 'cffi': '1.17.1', 'pycparser': '2.22'}:
        raise RuntimeError('Provider dependencies do not match the pinned profile')
    from pqcrypto.kem import ml_kem_768
    from pqcrypto.sign import ml_dsa_65
    from pqcrypto._kem import ml_kem_768 as kem_native
    from pqcrypto._sign import ml_dsa_65 as dsa_native
    if (ml_kem_768.PUBLIC_KEY_SIZE, ml_kem_768.SECRET_KEY_SIZE, ml_kem_768.CIPHERTEXT_SIZE,
            ml_kem_768.PLAINTEXT_SIZE) != (1184, 2400, 1088, 32):
        raise RuntimeError('Unexpected ML-KEM-768 interface sizes')
    if (ml_dsa_65.PUBLIC_KEY_SIZE, ml_dsa_65.SIGNATURE_SIZE) != (1952, 3309):
        raise RuntimeError('Unexpected ML-DSA-65 interface sizes')
    lib = ctypes.CDLL(dsa_native.__file__)
    verify = lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx
    verify.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                       ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    verify.restype = ctypes.c_int
    artifacts = []
    for module in (ml_kem_768, ml_dsa_65, kem_native, dsa_native):
        path = Path(module.__file__)
        artifacts.append({'module': module.__name__, 'file': path.name,
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    return Adapter(ml_kem_768, verify), {'versions': versions, 'python': platform.python_version(),
                                      'platform': platform.platform(), 'machine': platform.machine(),
                                      'isolation_checks': isolation,
                                      'artifacts': artifacts, 'build_flags': 'Not exposed by the prebuilt wheel; wheel and native artifact hashes identify this build.'}


class Adapter:
    def __init__(self, kem, verifier):
        self.kem = kem
        self.verifier = verifier

    def decapsulate(self, dk, ciphertext):
        return self.kem.decrypt(dk, ciphertext)

    def verify_context(self, pk, message, context, signature):
        # The C API has no public-key length argument: never pass a short buffer.
        if len(pk) != 1952:
            raise ValueError('Adapter requires a 1952-byte public key')
        result = self.verifier(signature, len(signature), message, len(message), context, len(context), pk)
        if result not in (0, -1):
            raise RuntimeError('Unexpected native verifier return code')
        return result == 0
