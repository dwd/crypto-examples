
class Client:
    def __init__(self, username, authzid, password):
        from hpke import ciphersuites
        self._server_pk = None  # Gets this from the server on init
        self._client_pk = None  # Generates during init
        self._client_sk = None  # Generates during init
        self._username = username
        self._authzid = authzid
        self._password = password
        self._ciphersuite = ciphersuites[7]
        self._session_step = None
        self._channel_binding = None
        self._hpke = None
        self._context = None
        self._cb_mode = False

    def sasl_init(self, channel_binding=None):
        self._session_step = None
        self._hpke = None
        self._context = None
        self._channel_binding = channel_binding
        if self._client_sk is None:
            self._client_sk, self._client_pk = self._ciphersuite.KEM().GenerateKeyPair()

    def sasl_step(self, data=None):
        import struct
        if self._session_step is None:
            # Need to perform init phase.
            if data is not None and self._server_pk is None:
                self._server_pk = self._ciphersuite.KEM().Unmarshal(data)
                self._session_step = 1
            elif self._server_pk is None:
                return None
            else:
                self._session_step = 1
        if self._session_step == 1:
            from hpke import HPKE
            hpke = HPKE(self._ciphersuite)
            enc, self._context = hpke.SetupAuthI(self._server_pk, self._client_sk, b''.join([
                self._username.encode('utf-8'),
                b'\0',
                self._authzid.encode('utf-8')
            ]))
            aad = b'N'
            if self._channel_binding:
                aad = b'Y' + self._channel_binding
            data = self._context.Seal(aad, self._password.encode('utf-8'))
            self._session_step = 2
            return b''.join([
                self._ciphersuite.KEM().Marshal(self._client_pk),
                struct.pack('!H', len(enc)),
                enc,
                struct.pack('!H', len(data))
            ])
        if self._session_step == 2:
            # TODO : Some kind of mutual auth?

