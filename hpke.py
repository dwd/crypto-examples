from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.kdf import hkdf
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

"""
This code is designed to align very closely to the pseudocode in
https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01

In general, most of the named functions are prefixed with "self",
because of the need to contain state, or simply divide them neatly.
"""

# Functions and definitions from §4

# These have wide deviation.
# pk is defined as part of KEM.
# Instead of "+", I use Concat
# Instead of "len", I use Len
# Instead of "^", I use Xor
# Rather than use "*", in the one instance I use bytes() instead.


def Concat(*args):
    import struct
    output = [b'']
    for x in args:
        if isinstance(x, int):
            output.append(struct.pack('B', x))
        elif isinstance(x, bytes):
            output.append(x)
    return b''.join(output)


def Len(octetstring):
    import struct
    return struct.pack('!H', len(octetstring))


def Xor(octetstring, value):
    byte = 0
    result = []
    for b in octetstring:
        import struct
        result.append(struct.pack('B', b ^ value[byte]))
        byte += 1
        byte %= len(value)
    return b''.join(result)


# This one isn't defined explicitly in -01.


def encode_big_endian(seq, L):
    import struct
    result = []
    while L > 0:
        result.append(struct.pack('B', seq % 0x100))
        seq = int(seq / 256)
        L -= 1
    return b''.join(reversed(result))


# §5.1, DH-Based KEM
# First, a DH matching the introduction, based on the X25519/X448
# interfaces in the Python cryptography library.


class XDH:
    def __init__(self, curvep, curves):
        self._curvep = curvep
        self._curves = curves

    def GenerateKeypair(self):
        sk = self._curves.generate()
        return sk, sk.public_key()

    def Marshal(self, pk):
        return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def Unmarshal(self, enc):
        return self._curvep.from_public_bytes(enc)

    def DH(self, sk, pk):
        return sk.exchange(pk)

    def pk(self, sk):
        return sk.public_key()


# Same interface, but now for the ECDH interface used for P-256 and P-521.

class ECDH:
    def __init__(self, curve):
        self.curve = curve

    def GenerateKeyPair(self):
        sk = ec.generate_private_key(self.curve, default_backend())
        return sk, sk.public_key()

    def Marshal(self, pk):
        return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def Unmarshal(self, enc):
        return ec.EllipticCurvePublicKeyWithSerialization.from_encoded_point(self.curve, enc)

    def DH(self, sk, pk):
        return sk.exchange(ec.ECDH(), pk)

    def pk(self, sk):
        return sk.public_key()


# Then the main code, which also matches the KEM interface in §5


class DHKEM:
    def __init__(self, dh):
        self.dh = dh

    def GenerateKeyPair(self):
        return self.dh.GenerateKeypair()

    def Marshal(self, pk):
        return self.dh.Marshal(pk)

    def Unmarshal(self, enc):
        return self.dh.Unmarshal(enc)

    def pk(self, sk):
        return self.dh.pk(sk)

    def Encap(self, pkR):
        skE, pkE = self.GenerateKeyPair()
        zz = self.dh.DH(skE, pkR)
        enc = self.Marshal(pkE)
        return zz, enc

    def Decap(self, enc, skR):
        pkE = self.Unmarshal(enc)
        return self.dh.DH(skR, pkE)

    def AuthEncap(self, pkR, skI):
        skE, pkE = self.GenerateKeyPair()
        zz = Concat(self.dh.DH(skE, pkR), self.dh.DH(skI, pkR))
        enc = self.Marshal(pkE)
        return zz, enc

    def AuthDecap(self, enc, skR, pkI):
        pkE = self.Unmarshal(enc)
        return Concat(self.dh.DH(skR, pkE), self.dh.DH(skR, pkI))


# KDF interface defined in §5


class HKDF:
    class Extractor(hkdf.HKDF):
        def __init__(self, algorithm, length, salt, info, backend):
            hkdf.HKDF.__init__(self, algorithm, length, salt, info, backend)

        def extract(self, ikm):
            return self._extract(ikm)

    class Expander(hkdf.HKDFExpand):
        def __init__(self, algorithm, length, info, backend):
            hkdf.HKDFExpand.__init__(self, algorithm, length, info, backend)

        def expand(self, prk):
            return self._expand(prk)

    def __init__(self, algorithm):
        self._algorithm = algorithm
        from cryptography.hazmat.backends import default_backend
        self._backend = default_backend()

    def Extract(self, salt, IKM):
        ex = HKDF.Extractor(self._algorithm, 1, salt, b'info', self._backend)
        return ex.extract(IKM)

    def Expand(self, PRK, info, L):
        ex = HKDF.Expander(self._algorithm, L, info, self._backend)
        return ex.expand(PRK)

    def Nh(self):
        return self._algorithm.digest_size


# AEAD interface defined in §5


OpenError = None


class AEAD:
    def __init__(self, algorithm, keysize, noncesize):
        self._algo = algorithm
        self._keysize = keysize
        self._noncesize = noncesize

    def Seal(self, key, nonce, aad, pt):
        algo = self._algo(key)
        return algo.encrypt(nonce, pt, aad)

    def Open(self, key, nonce, aad, ct):
        algo = self._algo(key)
        return algo.decrypt(nonce, ct, aad)

    def Nk(self):
        return self._keysize

    def Nn(self):
        return self._noncesize


# Ciphersuite, defined mostly by inference, with concerete definitions
# in §7


class Ciphersuite:
    def __init__(self, KEM : DHKEM, KDF : HKDF, AEAD : AEAD, value : int):
        self._kem = KEM
        self._kdf = KDF
        self._aead = AEAD
        self._value = value

    def value(self):
        import struct
        return struct.pack('!H', self._value)

    def KEM(self):
        return self._kem

    def KDF(self):
        return self._kdf

    def AEAD(self):
        return self._aead


# HPKE itself, defined in §6.


class HPKE:
    mode_base = 0x00
    mode_psk = 0x01
    mode_auth = 0x02

    # Context object, adapted from §6.4

    class Context:
        def __init__(self, AEAD: AEAD, key: bytes, nonce: bytes):
            self.key = key
            self.seq = 0
            self.nonce = nonce
            self._aead = AEAD

        def Nonce(self, seq):
            encSeq = encode_big_endian(seq, len(self.nonce))
            return Xor(self.nonce, encSeq)

        def Seal(self, aad, pt):
            ct = self._aead.Seal(self.key, self.Nonce(self.seq), aad, pt)
            self.seq += 1
            return ct

        def Open(self, aad, ct):
            pt = self._aead.Open(self.key, self.Nonce(self.seq), aad, ct)
            if pt == OpenError:
                return OpenError
            self.seq += 1
            return pt

    def __init__(self, ciphersuite : Ciphersuite):
        self._ciphersuite = ciphersuite

    # Forward up these to make it more readable.

    def GenerateKeypair(self):
        return self._ciphersuite.KEM().GenerateKeyPair()

    def Expand(self, PRK, info, L):
        return self._ciphersuite.KDF().Expand(PRK, info, L)

    def Extract(self, salt, IKM):
        return self._ciphersuite.KDF().Extract(salt, IKM)

    def Nk(self):
        return self._ciphersuite.AEAD().Nk()

    def Nn(self):
        return self._ciphersuite.AEAD().Nn()

    def Nh(self):
        return self._ciphersuite.KDF().Nh()

    def pk(self, sk):
        return self._ciphersuite.KEM().pk(sk)

    def Decap(self, enc, skR):
        return self._ciphersuite.KEM().Decap(enc, skR)

    def Encap(self, pkR):
        return self._ciphersuite.KEM().Encap(pkR)

    def AuthEncap(self, pkR, skI):
        return self._ciphersuite.KEM().AuthEncap(pkR, skI)

    def AuthDecap(self, enc, skR, pkI):
        return self._ciphersuite.KEM().AuthDecap(enc, skR, pkI)

    def ciphersuite(self):
        return self._ciphersuite.value()

    # Below are the Setup functions from §6
    # §6.1, Encryption to a Public Key

    def SetupCore(self, mode, secret, kemContext, info):
        # This has to be done slightly differently to the pseudocode, sorry!
        context = Concat(self.ciphersuite(), mode,
                         Len(kemContext), kemContext,
                         Len(info), info)
        key = self.Expand(secret, Concat(b"hpke key", context), self.Nk())
        nonce = self.Expand(secret, Concat(b"hpke nonce", context), self.Nn())
        return HPKE.Context(self._ciphersuite.AEAD(), key, nonce)

    def SetupBase(self, pkR, zz, enc, info):
        kemContext = Concat(enc, pkR)
        secret = self.Extract(bytes(self.Nh()), zz)
        return self.SetupCore(HPKE.mode_base, secret, kemContext, info)

    def SetupBaseI(self, pkR, info):
        zz, enc = self.Encap(pkR)
        return enc, self.SetupBase(pkR, zz, enc, info)

    def SetupBaseR(self, enc, skR, info):
        zz = self.Decap(enc, skR)
        return self.SetupBase(self.pk(skR), zz, enc, info)

    # §6.2, Authentication using a Pre-Shared Key

    def SetupPSK(self, pkR, psk, pskID, zz, enc, info):
        kemContext = Concat(enc, pkR, pskID)
        secret = self.Extract(psk, zz)
        return self.SetupCore(HPKE.mode_psk, secret, kemContext, info)

    def SetupPSKI(self, pkR, psk, pskID, info):
        zz, enc = self.Encap(pkR)
        return enc, self.SetupPSK(pkR, psk, pskID, zz, enc, info)

    def SetupPSKR(self, enc, skR, psk, pskID, info):
        zz = self.Decap(enc, skR)
        return self.SetupPSK(self.pk(skR), psk, pskID, zz, enc, info)

    # §6.3, Authentication using an Asymmetric Key

    def SetupAuth(self, pkR, pkI, zz, enc, info):
        kemContext = Concat(enc, pkR, pkI)
        secret = self.Extract(bytes(self.Nh()), zz)
        return self.SetupCore(HPKE.mode_auth, secret, kemContext, info)

    def SetupAuthI(self, pkR, skI, info):
        zz, enc = self.AuthEncap(pkR, skI)
        return enc, self.SetupAuth(pkR, self.pk(skI), zz, enc, info)

    def SetupAuthR(self, enc, skR, pkI, info):
        zz = self.AuthDecap(enc, skR, pkI)
        return self.SetupAuth(self.pk(skR), pkI, zz, enc, info)

# §7 Ciphersuite definitions. These are more complex than they should be,
# because the current draft appears to define them all to have only two
# different unique identifiers.

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from cryptography.hazmat.primitives.hashes import SHA256, SHA512

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

ciphersuites = dict()
ciphersuites[1] = Ciphersuite(
    DHKEM(ECDH(ec.SECP256R1)),
    HKDF(SHA256()),
    AEAD(AESGCM, 16, 12),
    1
)
ciphersuites[2] = Ciphersuite(
    DHKEM(ECDH(ec.SECP256R1)),
    HKDF(SHA256()),
    AEAD(ChaCha20Poly1305, 32, 12),
    2
)
ciphersuites[3] = Ciphersuite(
    DHKEM(XDH(X25519PublicKey, X25519PrivateKey)),
    HKDF(SHA256()),
    AEAD(AESGCM, 16, 12),
    3
)
ciphersuites[4] = Ciphersuite(
    DHKEM(XDH(X25519PublicKey, X25519PrivateKey)),
    HKDF(SHA256()),
    AEAD(ChaCha20Poly1305, 32, 12),
    4
)
ciphersuites[5] = Ciphersuite(
    DHKEM(ECDH(ec.SECP521R1)),
    HKDF(SHA512()),
    AEAD(AESGCM, 32, 12),
    5
)
ciphersuites[6] = Ciphersuite(
    DHKEM(ECDH(ec.SECP521R1)),
    HKDF(SHA512()),
    AEAD(ChaCha20Poly1305, 32, 12),
    6
)
ciphersuites[7] = Ciphersuite(
    DHKEM(XDH(X448PublicKey, X448PrivateKey)),
    HKDF(SHA512()),
    AEAD(AESGCM, 32, 12),
    7
)
ciphersuites[8] = Ciphersuite(
    DHKEM(XDH(X448PublicKey, X448PrivateKey)),
    HKDF(SHA512()),
    AEAD(ChaCha20Poly1305, 32, 12),
    8
)
