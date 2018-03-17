# Python program to implement server side of chat room.
from socket import socket, SOL_SOCKET, SO_REUSEADDR, AF_INET, SOCK_STREAM
from request import Request
from key_fragments_map import key_frag_map
import cmd_types
import select
import sys
import queue
from threading import Thread
from umbral import pre, keys, config, fragments

ENCODING = "utf-8"
NUM_CLIENTS = 10
BUFFER_SIZE = 2048*30

ip_to_id = {} #Indexed by ip, returns (id,pk)
pk_to_id = {} #Indexed by pk, returns id
key_fragment_arr = None #Indexed by [from][to] contains corresponding fragment
available_ids = None
list_of_clients = []
ctr_id = 0


def print_map():
    for i in range(NUM_CLIENTS):
        print("row [{}]".format(i), key_fragment_arr.key_fragment_arr[i])

def clientthread(conn, addr):
    # sends a message to the client whose user object is conn
    # conn.send("Welcome to this chatroom!".encode(ENCODING))
    global key_fragment_arr
    usr_ip = addr[0]
    while True:
            # Make sure that encoding will not violate the check on `message` below
            message = conn.recv(BUFFER_SIZE).decode(ENCODING)
            if message:
                # Parse command
                # print("The message I'm parsing is {}".format(message))
                try:
                    request = Request.deserialize(message)
                except:
                    raise ValueError("Can't deserialize JSON data")
                cmd = request.cmd
                args = request.args
                print("[RECEIVED-cmd] : {0}".format(cmd))
                if cmd == cmd_types.REGISTER:
                    pubKey = args['pub_key']
                    register(usr_ip, conn, pubKey)
                    # Ask the user for kfrags (after sending all PKs)
                elif cmd == cmd_types.MSG_TO_NODE:
                    ''' 
                    User should expect the follow from the user:
                        - ciphertext
                        - capsoule
                    Now we go through all the other users and compute cfrag for each, and send it
                    '''
                    alice_capsule = pre.Capsule.from_bytes(args['sender_capsule'])
                    alice_ciphertext = args['ciphertext']
                    alice_pk = args['sender_publickey']
                    share_cfrags(alice_pk, alice_capsule, alice_ciphertext, conn)
                elif cmd == cmd_types.SEND_FRG_SAMPLE:
                    src_pubkey = args['client_pubkey']
                    src_id = pk_to_id[src_pubkey]
                    dst_pubkey = args['new_pubkey']
                    dst_id = pk_to_id[dst_pubkey]
                    khfrag_sample = args['khfrag_sample']
                    khfrag_sample = [fragments.KFrag.from_bytes(sample) for sample in khfrag_sample]
                    # print("Got the following kfrag samples {0}".format(khfrag_sample))
                    key_fragment_arr.set_fragment(src_id, dst_id, khfrag_sample)
                    # print_map()
                
                # elif cmd == cmd_types.SEND_PLAINTEXT:
                #     args = request.args
                #     msg_received = args['msg']
                #     # Calls broadcast function to send message to all
                #     message_to_send = "<" + usr_ip + "> " + msg_received
                #     print(message_to_send)
                #     new_req = Request.send_plaintext_request(message_to_send)
                #     broadcast(new_req.serialize(), conn)
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
 

def share_cfrags(usr_pk, sender_capsule, sender_ciphertext, connection):
    global key_fragment_arr
    for clients in list_of_clients:
        if clients!=connection:
            # try:
            # get sender PK from ip
            src_pk = usr_pk
            # print("my type is {}".format(type(src_pk)))
            src_id = pk_to_id[src_pk]
            dst_ip = clients.getpeername()[0]
            dst_id = ip_to_id[dst_ip][0]
            # get kfrag for sender and clients
            kfrags = key_fragment_arr.get_fragment(src_id, dst_id)
            # Compute the cfrag
            cfrags = [pre.reencrypt(kfrag, sender_capsule).to_bytes() for kfrag in kfrags]
            # Send the sender_capsule, cfrag, senderPk, sender_ciphertext
            req = Request.send_cfrag_request(sender_capsule.to_bytes(), cfrags, src_pk, sender_ciphertext)
            clients.send(req.serialize().encode(ENCODING))
            # except:
            #     print("cfrag sharing FAILED!")
            #     clients.close()
            #     # if the link is broken, we remove the client
            #     remove(clients, connection)
    
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
        # print('2')
        client_info = ip_to_id[client_ip]
        if(client_ip == ip):
            # print('3')
            continue;
        elif(len(client_info) == 3 ):
            # print('4')
            client_id = client_info[0]
            client_pubkey = client_info[1]
            print("the type is {}".format(type(client_pubkey)))
            pk_arr += [client_pubkey]
        else:
            print('[ERROR] in Registration step 2')
            exit()
    print('[REG STAGE TWO] End, Collected '+ str(len(pk_arr)) + ' NUM PKS')
    if(len(pk_arr)>0):
        req = Request.send_all_pks_request(pk_arr)
        ser_req = req.serialize()
        conn.send(ser_req.encode(ENCODING))
        print('[REG STAGE TWO] Client Pks Found '+ ser_req)
    return

def register(ip, conn, new_client_pubkey):
    '''
        Registration phase 1 
    '''
    print("[BEGIN] Node Registration Routine")
    global ip_to_id
    global pk_to_id
    usr_id = get_id()
    if ip in ip_to_id:
        print("Client already registered.")
    ip_to_id[ip] = (usr_id, new_client_pubkey, conn)
    pk_to_id[new_client_pubkey] = usr_id
    print("[REG STAGE ONE] Registered [id: "+ str(usr_id)+ ", Pk: "+str(new_client_pubkey)+ ']')
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