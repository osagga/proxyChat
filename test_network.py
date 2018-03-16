from umbral import pre, keys, config
from nucypher import MockNetwork

# Setup pypre
config.set_default_curve()


# Generate Keys and setup mock network
alice_privkey = keys.prePrivateKey.gen_key()
alice_pubkey = alice_privkey.get_pubkey()

bob_privkey = keys.prePrivateKey.gen_key()
bob_pubkey = bob_privkey.get_pubkey()

mock_kms = MockNetwork()

# Encrypt some data
plaintext = b'attack at dawn!'
ciphertext, capsule = pre.encrypt(alice_pubkey, plaintext)


# Perform split-rekey and grant re-encryption policy
alice_kfrags, _ = pre.split_rekey(alice_privkey, bob_pubkey, 10, 20)
assert len(alice_kfrags) == 20

policy_id = mock_kms.grant(alice_kfrags)
assert type(policy_id) == str


# Perform re-encryption request
bob_cfrags = mock_kms.reencrypt(policy_id, capsule, 10)
assert len(bob_cfrags) == 10


# Simulate capsule handoff,
bob_capsule = capsule
for cfrag in bob_cfrags:
    bob_capsule.attach_cfrag(cfrag)

decrypted_data = pre.decrypt(bob_capsule, bob_privkey, ciphertext, alice_pubkey)
assert decrypted_data == plaintext


# Perform revoke request
mock_kms.revoke(policy_id)


# This should throw a `ValueError`.
try:
    mock_kms.reencrypt(policy_id, capsule, 10)
except ValueError:
    print("An Error was thrown indicating the expected response. Tests have been run.")
