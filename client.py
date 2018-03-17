# Python program to implement client side of chat room.
import socket
import select
import sys
from request import Request
from umbral import pre, keys, config


ENCODING = "utf-8"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if len(sys.argv) != 3:
    print("Correct usage: script, IP address, port number")
    exit()
IP_address = str(sys.argv[1])
Port = int(sys.argv[2])
server.connect((IP_address, Port))
 
def key_gen():
    config.set_default_curve()
    priv_key = keys.UmbralPrivateKey.gen_key()
    pub_key = priv_key.get_pubkey()
    return (priv_key, pub_key)


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
            message = socks.recv(2048).decode(ENCODING)
            print(message)
        else:
            message = sys.stdin.readline()
            #server.send(message.encode(ENCODING))
            req = Request.send_plaintext_request(message)
            ser_reg = req.serialize()
            server.send(ser_reg.encode(ENCODING))
            
            sys.stdout.write("<You>")
            sys.stdout.write(message)
            sys.stdout.flush()
server.close()




