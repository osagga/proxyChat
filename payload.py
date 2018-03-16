import jsonpickle
from umbral import keys

#Will be in Node and Client
class Payload(object):
	def __init__(self, cmd, args):
		self.cmd = cmd
		self.args = args

def serialize_pubkey(umbral_pubkey):
    umbral_pubkey = UmbralPrivateKey.gen_key().get_pubkey()
    new_keypair = keypairs.Keypair(umbral_pubkey)

    pubkey_bytes = new_keypair.serialize_pubkey()
    assert pubkey_bytes == bytes(umbral_pubkey)

    pubkey_b64 = new_keypair.serialize_pubkey(as_b64=True)
    assert pubkey_b64 == umbral_pubkey.to_bytes()



































