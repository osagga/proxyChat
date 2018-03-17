# Python program to implement server side of chat room.
from socket import socket, SOL_SOCKET, SO_REUSEADDR, AF_INET, SOCK_STREAM
from request import Request
from key_fragments_map import key_frag_map
import cmd_types
import select
import sys
import queue
from threading import Thread
from umbral import keys, config

ENCODING = "utf-8"
NUM_CLIENTS = 100
BUFFER_SIZE = 2048

ip_to_id = {} #Indexed by ip, returns (id,pk)
key_fragment_arr = None #Indexed by [from][to] contains corresponding fragment
available_ids = None
list_of_clients = []
ctr_id = 0

def clientthread(conn, addr):
    # sends a message to the client whose user object is conn
    # conn.send("Welcome to this chatroom!".encode(ENCODING))
    usr_ip = addr[0]
    while True:
            # Make sure that encoding will not violate the check on `message` below
            message = conn.recv(BUFFER_SIZE).decode(ENCODING)
            if message:
                # Parse command
                try:
                    request = Request.deserialize(message)
                except:
                    raise ValueError("Can't deserialize JSON data")
                cmd = request.cmd
                args = request.args
                print("[RECEIVED-cmd] : {0}".format(cmd))
                if cmd == cmd_types.REGISTER:
                    pubKey = get_pubKey(args)
                    register(usr_ip, conn, pubKey)
                    # Ask the user for kfrags (after sending all PKs)
                elif cmd == cmd_types.MSG_TO_USER:
                    ''' 
                    User should expect the follow from the user:
                        - ciphertext
                        - capsoule
                    Now we go through all the other users and compute cfrag for each, and send it
                    '''
                    alice_capsule = args[0]
                    alice_ciphertext = args[1]
                    share_cfrags(usr_ip, alice_capsule, alice_ciphertext)
                elif cmd == cmd_types.SEND_FRG:
                    #TODO
                    continue
                elif cmd == cmd_types.SEND_PLAINTEXT:
                    args = request.args
                    msg_received = args['msg']
                    # Calls broadcast function to send message to all
                    message_to_send = "<" + usr_ip + "> " + msg_received
                    print(message_to_send)
                    new_req = Request.send_plaintext_request(message_to_send)
                    broadcast(new_req.serialize(), conn)
                elif cmd == cmd_types.USER_EXT:
                    #TODO
                    remove(usr_ip, conn)
                    continue
                else:
                    print("Invalid command received")
            else:
                """message may have no content if the connection
                is broken, in this case we remove the connection"""
                # print("The message is {}".format(message))
                remove(usr_ip, conn)
                exit()
 

def share_cfrags(usr_ip, sender_capsule, sender_ciphertext):
    for clients in list_of_clients:
        if clients!=connection:
            try:
                # get sender PK from ip
                src_pk = ip_to_id[ip][1]
                src_id = ip_to_id[ip][0]
                dst_ip = clients.getpeername()[0]
                dst_id = ip_to_id[dst_ip][0]
                # get kfrag for sender and clients
                kfrag = key_frag_map.get_fragment(src_id, dst_id)
                # Compute the cfrag
                cfrag = pre.reencrypt(kfrag, sender_capsule)
                # Send the sender_capsule, cfrag, senderPk, sender_ciphertext
                req = Request.send_cfrag_request(sender_capsule, cfrag, src_pk, sender_ciphertext)
                clients.send(req.serialize().encode(ENCODING))
            except:
                print("cfrag sharing FAILED!")
                clients.close()
                # if the link is broken, we remove the client
                remove(clients, connection)
    
def broadcast(message, connection):
    """Using the below function, we broadcast the message to all
    clients who's object is not the same as the one sending
    the message """
    for clients in list_of_clients:
        if clients!=connection:
            try:
                clients.send(message.encode(ENCODING))
            except:
                print("BROADCAST FAILED!")
                clients.close()
                # if the link is broken, we remove the client
                remove(clients, connection)

def notify_user(cmd, user_id, npk):
    #TODO
    return

def get_pubKey(args):
    '''
        Get the publicKey from the user passed args
    '''
    
    if 'pub_key' in args:
        return keys.UmbralPublicKey.from_bytes(args['pub_key'])
    else:
        raise ValueError("Can't find user PublicKey")


def remove(ip, connection): 
    '''
        User of <ip> is remove from the chat 
    '''
    # try:
    #     connection = ip_to_id[ip][2]
    # except:
    #     print("Can't find the client socket.")
    
    if connection in list_of_clients:
        list_of_clients.remove(connection)
    return
	# rem_id = ip_to_id[ip]
	
	# for _from in key_fragment_arr: 
	# 	set_fragment(_from, rem_id, None)

	# for usr in all_users:
	# 	set_fragment(rem_id, usr, None)
	
	# available_ids += [rem_id]

def send_pks_to_client(ip, conn):
    print('[REG STAGE 2] Start')
    pk_arr = []

    for client_ip in ip_to_id:
        print('2')
        client_info = ip_to_id[client_ip]
        if(client_ip == ip):
            print('3')
            continue;
        elif(len(client_info) == 3 ):
            print('4')
            client_id = client_info[0]
            client_pubkey = client_info[1]
            pk_arr += [client_pubkey]
        else:
            print('[ERROR] in Registration step 2')
            exit()
    print('[REG STAGE TWO] End, Collected '+ str(len(pk_arr)) + ' NUM PKS')
    if(len(pk_arr)>0):
        req = Request.send_all_pks_request(pk_arr)
        ser_req = req.serialize()
        print('[REG STAGE TWO] Client Pks Found '+ ser_req)
    return

def register(ip, conn, new_client_pubkey):
    '''
        Registration phase 1 
    '''
    print("[BEGIN] Node Registration Routine")
    global ip_to_id
    usr_id = get_id()
    if ip in ip_to_id:
        print("Client already registered.")
    ip_to_id[ip] = (usr_id, new_client_pubkey, conn)
    print("[REG STAGE ONE] Registered [id: "+ str(id)+ ", Pk: "+str(new_client_pubkey.to_bytes())+ ']')
    if len(ip_to_id) > 1:
        send_pks_to_client(ip,conn)
        notify_clients_of_new_user(new_client_pubkey, conn)
    return

def notify_clients_of_new_user(new_client_pubkey, conn):
    message_to_send = "New user joined!!!!"
    new_req = Request.send_plaintext_request(message_to_send)
    req = Request.send_new_user_notify_request(new_client_pubkey)
    broadcast(new_req.serialize(), conn)
    ser_req = req.serialize()
    print(message_to_send)
    print("[BEGIN] Broadcast New User Request to Clients ")
    broadcast(ser_req, conn)

def init_ids():
    global available_ids
    available_ids = queue.Queue()
    return

def get_id():
    global ctr_id
    if not available_ids.empty():
        return available_ids.get()
    else:
        ctr_id += 1
        return ctr_id 

def main():
    """The first argument AF_INET is the address domain of the
    socket. This is used when we have an Internet Domain with
    any two hosts The second argument is the type of socket.
    SOCK_STREAM means that data or characters are read in
    a continuous flow."""
    global key_fragment_arr
    config.set_default_curve()
    init_ids() #queue containing the available ids
    
    key_fragment_arr = key_frag_map(NUM_CLIENTS)

    server = socket(AF_INET, SOCK_STREAM)
    server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    
    # checks whether sufficient arguments have been provided
    if len(sys.argv) != 3:
        print("Correct usage: script, IP address, port number")
        exit()
    
    # takes the first argument from command prompt as IP address
    IP_address = str(sys.argv[1])
    
    # takes second argument from command prompt as port number
    Port = int(sys.argv[2])
    
    """
    binds the server to an entered IP address and at the
    specified port number.
    The client must be aware of these parameters
    """
    server.bind((IP_address, Port))
    
    """
    listens for 100 active connections. This number can be
    increased as per convenience.
    """
    server.listen(NUM_CLIENTS)

    while True:
    
        """Accepts a connection request and stores two parameters, 
        conn which is a socket object for that user, and addr 
        which contains the IP address of the client that just 
        connected"""
        conn, addr = server.accept()
    
        """Maintains a list of clients for ease of broadcasting
        a message to all available people in the chatroom"""
        list_of_clients.append(conn)
    
        # prints the address of the user that just connected
        print(addr[0] + " connected")
    
        # creates and individual thread for every user 
        # that connects
        Thread(target=clientthread,args=(conn,addr)).start()
    
    conn.close()
    server.close()

if __name__ == "__main__":
    main()