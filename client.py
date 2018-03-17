# Python program to implement client side of chat room.
import socket
import select
import sys
import cmd_types
from request import Request
from umbral import pre, keys, config, fragments

PROXY_ENCRYPTION_DISABLED = False
ENCODING = "utf-8"
THRESHOLD_M = 10
THRESHOLD_N = 20 
BUFFER_SIZE = 2048*9
client_public_keys = []
def key_gen():
    config.set_default_curve()
    priv_key = keys.UmbralPrivateKey.gen_key()
    pub_key = priv_key.get_pubkey()
    return (priv_key, pub_key)

def main():
    if len(sys.argv) != 3:
        print("Correct usage: script, IP address, port number")
        exit()

    ip_to_pk = {} # Indexed by ip, returns (pk)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IP_address = str(sys.argv[1])
    Port = int(sys.argv[2])
    server.connect((IP_address, Port))
    (user_priv_key, user_pub_key) = key_gen()

    user_pub_key = user_pub_key.to_bytes()

    reg_req = Request.register_request(user_pub_key)
    ser_reg_req = reg_req.serialize()
    server.send(ser_reg_req.encode(ENCODING))
    print('[SENT] Request : '+ ser_reg_req)

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
                # print("The message is {}".format(message))
                # Parse command
                try:
                    request = Request.deserialize(message)
                except:
                    raise ValueError("Can't deserialize JSON data")
                    exit()
                # print("The request I got is as follow {0}".format(request))
                cmd = request.cmd
                args = request.args
                print("[RECEIVED-CMD] : {0}".format(cmd))
                if cmd == cmd_types.SEND_ALL_PKS:
                    #TODO
                    continue
                elif cmd == cmd_types.NEW_USR:
                    print('[CLIENT] Received new pubkey, creating khfrag')
                    #Get the public key of the new user
                    new_pubkey = args['new_pubkey']
                    #Compute the re-encryption keys
                    # print("the type is" + str(type(new_pubkey)))
                    khfrags = pre.split_rekey(user_priv_key, keys.UmbralPublicKey.from_bytes(new_pubkey), THRESHOLD_M, THRESHOLD_N)
                    #Create a sample to distribute the shares to each Node                    
                    khfrags_sample = []
                    for i in range(0,THRESHOLD_M):
                        khfrags_sample += [khfrags[i].to_bytes()]
                    #Create the request
                    req = Request.send_new_user_khfrag_samples_request(client_pubkey = user_pub_key, new_user_pubkey = new_pubkey, khfrag_sample = khfrags_sample)
                    req_ser = req.serialize()
                    print('[CLIENT] Created KhFrag Sample Request = ' + req_ser)
                    server.send(req_ser.encode(ENCODING))
                    continue
                elif cmd == cmd_types.MSG_TO_USER:
                    '''
                        Args should contain three things:
                            - Alice's PK
                            - Alice's capsule (encryptes symetric key)
                            - Alice's ciphertext
                            - cfrag/s (one from each node)
                    '''
                    alice_pub_key = keys.UmbralPublicKey.from_bytes(args['sender_publickey'])
                    A_capsule = pre.Capsule.from_bytes(args['sender_capsule'])
                    bob_capsule = A_capsule #This is just to stick to the demo
                    A_ciphertext = args['ciphertext']
                    cfrags = args['cfrag']
                    for cfrag in cfrags:
                        bob_capsule.attach_cfrag(fragments.CapsuleFrag.from_bytes(cfrag))
                    message = pre.decrypt(bob_capsule, user_priv_key, A_ciphertext, alice_pub_key)
                    print("<{0}> {1}".format(alice_pub_key.to_bytes()[:10], message.decode(ENCODING))) 
                # elif cmd == cmd_types.SEND_PLAINTEXT:
                #     args = request.args
                #     msg_received = args['msg']
                #     print(msg_received)
                else:
                    print("Invalid command received")
            else:
                # Here we do the Enryption (this is the user input)
                message = sys.stdin.readline()

                # if not message:
                #     continue

                #server.send(message.encode(ENCODING))

                if(PROXY_ENCRYPTION_DISABLED):
                    req = Request.send_plaintext_request(message)
                    ser_reg = req.serialize()
                    server.send(ser_reg.encode(ENCODING))
                else:
                    ciphertext, sender_capsule = pre.encrypt(keys.UmbralPublicKey.from_bytes(user_pub_key), message.encode(ENCODING))
                    sender_capsule = sender_capsule.to_bytes()
                    # print('Ciphertext of :' + message)
                    # print(ciphertext)
                    req = Request.send_ciphertext_request(sender_capsule = sender_capsule, ciphertext = ciphertext, sender_publickey = user_pub_key)
                    ser_req = req.serialize()
                    # print(ser_req)
                    server.send(ser_req.encode(ENCODING))
                sys.stdout.write("<You>")
                sys.stdout.write(message)
                sys.stdout.flush()
    server.close()


if __name__ == "__main__":
    main()