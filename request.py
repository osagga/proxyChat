import jsonpickle
from umbral import pre, keys, config
import cmd_types

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
		pk_bytes = new_pub_key
		return cls(cmd = cmd_types.REGISTER, args = {'pub_key': pk_bytes})

	@classmethod
	def send_plaintext_request(cls, msg):
		return cls(cmd = cmd_types.SEND_PLAINTEXT, args = {'msg': msg})

	@classmethod
	def send_all_pks_request(cls, pk_arr):
		'''
			TODO TEST THIS
			pk_arr contain an array of UmbralPublicKey instances
			This function
			1. Serializes each UmbralPublicKey with .to_bytes()
			2. Serializes the array of the serialized UmbralPublicKey 
			3. Adds this to the args variable with key 'pks'
			4. Initializes the request
		'''
		serPks_arr = [pk for pk in pk_arr]
		#serPks_arr an array of serialized UmbralPublicKey. Array of strings
		serialized_serPks_arr = jsonpickle.encode(serPks_arr)
		#A string representing serPks_arr
		req_args = {'pks':serialized_serPks_arr}
		return cls(cmd = cmd_types.SEND_ALL_PKS, args = req_args)

	@classmethod
	def send_ciphertext_request(cls, sender_capsule, ciphertext, sender_publickey):
		req_args = {}
		req_args['ciphertext'] = ciphertext
		req_args['sender_capsule'] = sender_capsule
		req_args['sender_publickey'] = sender_publickey
		return cls(cmd = cmd_types.NEW_MSG, args = req_args)

	@classmethod
	def send_cfrag_request(cls, sender_capsule, cfrag, sender_publickey, sender_ciphertext):
		req_args = {}
		req_args['ciphertext'] = sender_ciphertext
		req_args['cfrag'] = cfrag
		req_args['sender_capsule'] = sender_capsule
		req_args['sender_publickey'] = sender_publickey
		return cls(cmd = cmd_types.MSG_TO_USER, args = req_args)
	
	@classmethod
	def send_new_user_notify_request(cls, new_user_pubkey):
		req_args = {'new_pubkey' : new_user_pubkey}
		return cls(cmd = cmd_types.NEW_USR, args = req_args)


	@classmethod
	def send_new_user_khfrag_samples_request(cls, client_pubkey ,new_user_pubkey, khfrag_sample):
		req_args = {}
		req_args['client_pubkey'] = client_pubkey
		req_args['new_pubkey'] = new_user_pubkey
		req_args['khfrag_sample'] = khfrag_sample
		return cls(cmd = cmd_types.SEND_FRG_SAMPLE, args = req_args)


def test_register_request():
	config.set_default_curve()
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
	#Create the public key objects from the bytes in the request arguments
	pub_key_1 = keys.UmbralPublicKey.from_bytes(new_req.args['pub_key'])
	pub_key_2 = keys.UmbralPublicKey.from_bytes(my_req.args['pub_key'])

	assert(pub_key_1.point_key == pub_key_2.point_key)

	print('SUCCESS')
	
# test_register_request()

'''
Key Serialization and payload creation	
(1) Serialize the key
(2) Create payload instance 
	(-) Set cmd to SEND_FRAG
	(-) 

'''


