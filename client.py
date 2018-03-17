#! /usr/bin/env python3

# Python program to implement client side of chat application.

import socket
import select
import sys
import cmd_types
from request import Request
from umbral import pre, keys, config, fragments

# Encoding used to transmit strings across the network.
ENCODING = "utf-8"

# Dynamic variables that can be used when implmenting in a dencentralized mode.
THRESHOLD_M = 10 # The 'threshold' of the Shamir's Secret Sharing of the re-encryption key
THRESHOLD_N = 20 # The total number of shares issued (to be distrbuted on the nodes in the network)

# The size of the incoming packets (in Bytes)
BUFFER_SIZE = 2048*30

# List with the public keys of the current observerd clients in the network (a PKI alternative)
client_public_keys = []

def key_gen():
    '''
        Generate a key pair for the current client under the default choice of Eliptic Curve.
    '''
    config.set_default_curve()
    priv_key = keys.UmbralPrivateKey.gen_key()
    pub_key = priv_key.get_pubkey()
    return (priv_key, pub_key)

def main():

    if len(sys.argv) != 3:
        print("Correct usage: script, IP address, port number")
        exit()

    ip_to_pk = {} # Indexed by ip, returns pk

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IP_address = str(sys.argv[1])
    Port = int(sys.argv[2])
    server.connect((IP_address, Port))

    # Generate a key pair to be used for the protocol
    (user_priv_key, user_pub_key) = key_gen()

    # Serialize the user_pub_key for future transmission.
    user_pub_key = user_pub_key.to_bytes()

    # Send a registartion request to the nodes in the network.
    reg_req = Request.register_request(user_pub_key)
    ser_reg_req = reg_req.serialize()
    server.send(ser_reg_req.encode(ENCODING))

    while True:

        # maintains a list of possible input streams
        sockets_list = [sys.stdin, server]

        """ There are two possible input situations. Either the
        user wants to give  manual input to send to other people,
        or the server is sending a message  to be printed on the
        screen. Select returns from sockets_list, the stream that
        is reader for input. So for example, if the server wants
        to send a message, then the if condition will hold true
        below.If the user wants to send a message, the else
        condition will evaluate as true"""
        read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])

        for socks in read_sockets:
            if socks == server:
                message = socks.recv(BUFFER_SIZE).decode(ENCODING)

                try:
                    request = Request.deserialize(message)
                except:
                    raise ValueError("Can't deserialize JSON command")
                    exit()
                
                cmd = request.cmd
                args = request.args
                
                # Parse the recived command
                if cmd == cmd_types.SEND_ALL_PKS:
                    '''
                        After joining the network, we recieve a list of the current active users (by their Public Keys)
                        We parse the given list to generate fragments of the re-encryption key corresponding to each
                        public key reciver (we assume open permission to any user in the group chat).
                    '''
                    pubkey_arr = args['pks']

                    for new_pubkey in pubkey_arr:
                        # We generate N shares so that it would be distributed over the 'N' nodes of the network.
                        khfrags = pre.split_rekey(user_priv_key, keys.UmbralPublicKey.from_bytes(new_pubkey), THRESHOLD_M, THRESHOLD_N)
                        # Create a sample to distribute the shares to each Node (To simulate a decentralized scenario)                
                        khfrags_sample = []
                        for i in range(0,THRESHOLD_M):
                            khfrags_sample += [khfrags[i].to_bytes()]
                        # Send the payload of the fragmented re-encryption keys to the nodes in the network
                        req = Request.send_new_user_khfrag_samples_request(client_pubkey = user_pub_key, new_user_pubkey = new_pubkey, khfrag_sample = khfrags_sample)
                        server.send(req.serialize().encode(ENCODING))
                elif cmd == cmd_types.NEW_USR:
                    '''
                        While on the network, if any new user joins the network, the nodes would send the new user's PublicKey
                        to the all the users currenlty using the group chat. Then users would compute the re-encryption key
                        for that specific user and send the fragments to the nodes in the network.
                    '''
                    
                    #Get the public key of the new user
                    new_pubkey = args['new_pubkey']
                    #Compute the re-encryption keys
                    khfrags = pre.split_rekey(user_priv_key, keys.UmbralPublicKey.from_bytes(new_pubkey), THRESHOLD_M, THRESHOLD_N)
                    #Create a sample to distribute the shares to each Node                    
                    khfrags_sample = []
                    for i in range(0,THRESHOLD_M):
                        khfrags_sample += [khfrags[i].to_bytes()]
                    
                    # Send the payload of the fragmented re-encryption key to the nodes in the network
                    req = Request.send_new_user_khfrag_samples_request(client_pubkey = user_pub_key, new_user_pubkey = new_pubkey, khfrag_sample = khfrags_sample)
                    req_ser = req.serialize()
                    server.send(req_ser.encode(ENCODING))
                elif cmd == cmd_types.MSG_TO_USER:
                    '''
                        While on the network, and a user sends a message to the group chat. The nodes will compute the
                        Capsule fragments corresponding to each recieving user and send it to them. The user then would
                        combine all the needed fragments (At least M) and then decrypt and verify the plaintext.
                    '''
                    # Deserialization
                    alice_pub_key = keys.UmbralPublicKey.from_bytes(args['sender_publickey'])
                    A_capsule = pre.Capsule.from_bytes(args['sender_capsule'])
                    bob_capsule = A_capsule #This is just to stick to the demo analogy.
                    A_ciphertext = args['ciphertext']
                    cfrags = args['cfrag']

                    # Combining the fragments of the Capsule.
                    for cfrag in cfrags:
                        bob_capsule.attach_cfrag(fragments.CapsuleFrag.from_bytes(cfrag))

                    # Decrypting the ciphertext
                    plaintext = pre.decrypt(bob_capsule, user_priv_key, A_ciphertext, alice_pub_key)

                    print("<{0}> {1}".format(alice_pub_key.to_bytes()[:10], plaintext.decode(ENCODING)))
                
                elif cmd == cmd_types.SEND_PLAINTEXT:
                        msg_received = args['msg']
                        print(msg_received)
                else:
                    print(cmd)
                    print("Invalid command received")
            else:
                # Here we do the Enryption (on the user input)
                user_input = sys.stdin.readline()

                # Generate the ciphertext and sender_capsule
                ciphertext, sender_capsule = pre.encrypt(keys.UmbralPublicKey.from_bytes(user_pub_key), user_input.encode(ENCODING))
                sender_capsule = sender_capsule.to_bytes()

                # We send the ciphertext, sender_capsule and the user PublicKey to the nodes.
                req = Request.send_ciphertext_request(sender_capsule = sender_capsule, ciphertext = ciphertext, sender_publickey = user_pub_key)
                ser_req = req.serialize()
                server.send(ser_req.encode(ENCODING))

                # We still print the `user_input` to the user's own screen (optional)
                sys.stdout.write("<You>")
                sys.stdout.write(user_input)
                sys.stdout.flush()

    server.close()


if __name__ == "__main__":
    main()