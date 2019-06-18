import hpke

h = hpke.HPKE(hpke.ciphersuites[3])

skI, pkI = h.GenerateKeypair()

# Normally, the recipient and initiator would be different people,
# and would exchange keys over a transfer medium of some kind.

skR, pkR = h.GenerateKeypair()

info = b"Some information about the context, maybe the sender's identity"
aad = b"Some (auth, but plaintext) data to send alongside the encrypted data"

enc, ctxtI = h.SetupAuthI(pkR, skI, info)
ct = ctxtI.Seal(aad, b"Plaintext goes here")

class PDU:
    pass

pdu = PDU()

# This gets sent over the wire
pdu.enc = enc
pdu.info = info
pdu.aad = aad
pdu.ct = ct
print(repr(ct))

# Meanwhile, across town:

ctxtR = h.SetupAuthR(pdu.enc, skR, pkI, pdu.info)

pt = ctxtR.Open(pdu.aad, pdu.ct)

print(repr(pt))
