from mlstree import Node
from hpke import ciphersuites


class DS:
    def __init__(self):
        self.everyone = dict()

    def keys(self, whom):
        self.everyone[whom].public_key


class MS:
    def __init__(self):
        self.everyone = dict()

    def add_me(self, who):
        self.everyone[who.me] = who

    def broadcast(self, whom, msg):
        for who in whom:
            who.send(msg)


DirectoryService = DS()
MessageService = MS()


class MLSNodeData:
    def __init__(self):
        self.node_priv = None
        self.node_publ = None
        self.credential = None


class MLS:
    def __init__(self, me):
        self._tree = None
        self._mynode = None
        self.me = me
        self._ciphersuite = ciphersuites[3]


    def Hash(self, X):
        h = self._ciphersuite.KDF().H()()
        h.update(X)
        d = h.finalize()
        return d

    def HashLength(self):
        return self._ciphersuite.KDF().H().digest_length

    def Derive_Key_Pair(self, X):
        d = self.Hash(X)
        sk = self._ciphersuite.KEM().Unmarshal(d)
        pk = self._ciphersuite.KEM().pk(sk)
        return sk, pk

    def HKDF_Expand_Label(self, Secret, Label, Context, Length):
        import struct
        from hpke import Len
        label = b'mls10 ' + Label
        HkdfLabel = b''.join([
            struct.pack('!H', Length),
            Len(label),
            label,
            Len(Context),
            Context
        ])
        return self._ciphersuite.KDF().Expand(Secret, HkdfLabel, Length)

    def Derive_Secret(self, Secret, Label, Context):
        return self.HKDF_Expand_Label(Secret, Label, self.Hash(Context), self.HashLength())

    def HKDF_Extract(self, salt, IKM):
        self._ciphersuite.KDF().Extract(salt, IKM)

    def gen_secret(self):
        _sk, pk = self._ciphersuite.KEM().GenerateKeyPair()
        return self._ciphersuite.KEM().Marshal(pk)

    def RatchetTreeUpdate(self):
        X = self.gen_secret()
        path_secret = []
        node_secret = []
        for n in self._mynode.direct_path():
            path_secret.append(X)
            node_secret.append(self.HKDF_Expand_Label(X, b'node', b'', self.HashLength()))
            X = self.HKDF_Expand_Label(X, b'path', b'', self.HashLength())
            n.data().node_priv, n.data().node_pub = self.Derive_Key_Pair(node_secret[-1])
        encrypts = []
        s = 0
        for n in self._mynode.copath():
            for l in n.leaf_nodes():
                encrypts.append((l.data().node_pub, node_secret[s]))
            s += 1
        msg = []
        encrypts.reverse()
        for n in self._mynode.direct_path():
            msg.append((n.data().node_pub, encrypts.pop()))
        return msg




