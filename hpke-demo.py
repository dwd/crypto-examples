import hpke
import logging


class Initiator:
    def __init__(self, suites=None):
        self._log = logging.getLogger('Initiator')
        if suites is None:
            suites = [3]
        self._preferred_ciphersuites = suites
        self._log.debug("Ciphersuites: %s", repr(suites))
        self._hpke = [hpke.HPKE(hpke.ciphersuites[x]) for x in self._preferred_ciphersuites]
        self._log.debug("Created: %s", repr([h.ciphersuite() for h in self._hpke]))
        self._keypairs = [h.GenerateKeypair() for h in self._hpke]

    def pk(self, suite):
        which = self._preferred_ciphersuites.index(suite)
        if which != -1:
            return self._keypairs[which][1]

    def send(self, recip, plaintext):
        selected = None
        for suite in self._preferred_ciphersuites:
            if suite in recip.ciphersuites():
                selected = suite
        if selected is None:
            raise ValueError("Could not agree on a ciphersuite")
        self._log.debug("Sender: Using ciphersuite %d", selected)
        which = self._preferred_ciphersuites.index(suite)
        h = self._hpke[which]
        sk = self._keypairs[which][0]
        pk = recip.pk(selected)
        info = b'I am the Initiator'
        enc, context = h.SetupAuthI(pk, sk, info)
        recip.init(self, suite, enc, info)
        aad = b'Some (auth, but plaintext) data to send alongside the encrypted data'
        ciphertext = context.Seal(aad, plaintext)
        recip.msg(aad, ciphertext)


class Recipient:
    def __init__(self):
        self._log = logging.getLogger('Recipient')
        self._preferred_ciphersuites = [8, 7, 4, 3]
        self._hpke = [hpke.HPKE(hpke.ciphersuites[x]) for x in self._preferred_ciphersuites]
        self._keypairs = [h.GenerateKeypair() for h in self._hpke]
        self._context = None

    def ciphersuites(self):
        return self._preferred_ciphersuites

    def pk(self, suite):
        which = self._preferred_ciphersuites.index(suite)
        if which != -1:
            return self._keypairs[which][1]

    def init(self, initiator, suite, enc, info):
        which = self._preferred_ciphersuites.index(suite)
        h = self._hpke[which]
        sk = self._keypairs[which][0]
        pk = initiator.pk(suite)
        self._log.debug("HPKE ciphersuite: %s", repr(h.ciphersuite()))
        self._context = h.SetupAuthR(enc, sk, pk, info)
        self._log.info("Identity confirmed as %s", info)

    def msg(self, aad, ciphertext):
        plaintext = self._context.Open(aad, ciphertext)
        self._log.info("AAD authenticated as %s", aad)
        self._log.info("Plaintext is %s", plaintext)


logging.basicConfig(level=logging.DEBUG)

i = Initiator()
r = Recipient()

i.send(r, b'This is a demo')
