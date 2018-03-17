# Python program to implement client side of chat room.
import socket
import select
import sys
import cmd_types
from request import Request
from umbral import pre, keys, config

PROXY_ENCRYPTION_DISABLED = False
ENCODING = "utf-8"
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
                message = socks.recv(2048)
                print("The message is {}".format(message))
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
                    #TODO
                    continue
                elif cmd == cmd_types.NEW_MSG:
                    '''
                        Args should contain three things:
                            - Alice's IP
                            - Alice's capsule (encryptes symetric key)
                            - Alice's ciphertext
                            - cfrag/s (one from each node)
                    '''
                    A_IP = args[0]
                    A_capsule = args[1]
                    bob_capsule = A_capsule #This is just to stick to the demo
                    A_ciphertext = args[2]
                    cfrags = args[3]
                    for cfrag in cfrags:
                        bob_capsule.attach_cfrag(cfrag)
                    if A_IP in ip_to_pk:
                        alice_pub_key = ip_to_pk[A_IP]
                    else:
                        print("Missing sender's PublicKey (Can't decrypt the recived)")
                    message = pre.decrypt(bob_capsule, user_priv_key, A_ciphertext, alice_pub_key)
                    print(message)
                    #TODO
                    continue
                elif cmd == cmd_types.SEND_PLAINTEXT:
                    args = request.args
                    msg_received = args['msg']
                    print(msg_received)
                else:
                    print("Invalid command received")
            else:
                # Here we do the Enryption (this is the user input)
                message = sys.stdin.readline()
                #server.send(message.encode(ENCODING))

                if(PROXY_ENCRYPTION_DISABLED):
                    req = Request.send_plaintext_request(message)
                    ser_reg = req.serialize()
                    server.send(ser_reg.encode(ENCODING))
                else:
                    ciphertext, sender_capsule = pre.encrypt(user_pub_key, message.encode(ENCODING))
                    print('Ciphertext of :' + message)
                    print(ciphertext)
                    req = Request.send_ciphertext_request(sender_capsule = sender_capsule, ciphertext = ciphertext, sender_publickey = user_pub_key)
                    ser_req = req.serialize()
                    print(ser_req)
                    server.send(ser_req.encode(ENCODING))
                sys.stdout.write("<You>")
                sys.stdout.write(message)
                sys.stdout.flush()
    server.close()


if __name__ == "__main__":
    main()