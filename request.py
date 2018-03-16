import jsonpickle
from umbral import pre, keys, config


REGISTER = 'node_register'
NEW_MSG = 'node_new_msg'
SEND_FRG = 'usr_send_frag'
USER_EXT = 'usr_exit'

#Will be in Node and Client
class Request(object):
	def __init__(self, cmd, args):
		self.cmd = cmd
		self.args = args #JSON, dictionary with all the args 

	def serialize(self):
		return jsonpickle.encode(self)

	def deserialize(serialized_request):
		return jsonpickle.decode(serialized_request)

	@classmethod
	def register_request(cls, new_pub_key):
		'''
		params : 
			new_pub_key : keys.UmbralPublicKey
		return : 
			Request class instance 
		'''
		pk_bytes = new_pub_key.to_bytes()
		return cls(cmd = REGISTER, args = {'pub_key': pk_bytes})


def test_register_request():
	#Create private and public keys 
	priv_key = keys.UmbralPrivateKey.gen_key()
	pub_key = priv_key.get_pubkey()
	#Serialize the public key
	pk_bytes = pub_key.to_bytes()
	pub_key_test = keys.UmbralPublicKey.from_bytes(pk_bytes)
	assert(pub_key_test.point_key == pub_key.point_key) #Test umbral to, from bytes

	my_req = Request.register_request(pub_key)
	my_req_serialized = my_req.serialize()
	new_req = Request.deserialize(my_req_serialized)
	
	print(my_req.serialize())
	print(new_req.serialize())

	assert(new_req.serialize() == my_req.serialize())

	pub_key_1 = keys.UmbralPublicKey.from_bytes(new_req.args['pub_key'])
	pub_key_2 = keys.UmbralPublicKey.from_bytes(my_req.args['pub_key'])

	assert(pub_key_1.point_key == pub_key_2.point_key)

	print('SUCCESS')
	
test_register_request()

'''
Key Serialization and payload creation	
(1) Serialize the key
(2) Create payload instance 
	(-) Set cmd to SEND_FRAG
	(-) 

'''

































