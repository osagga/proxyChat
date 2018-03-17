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
    conn.send("Welcome to this chatroom!".encode(ENCODING))
    usr_ip = addr[0]
    while True:
            try:
                # Make sure that encoding will not violate the check on `message` below
                message = conn.recv(BUFFER_SIZE)
                if message:
                    # Parse command
                    try:
                        request = Request.deserialize(message)
                    except:
                        raise ValueError("Can't deserialize JSON data")
                    # print("The request I got is as follow {0}".format(request))
                    cmd = request.cmd
                    print("[RECEIVED-CMD] : {0}".format(cmd))
                    if cmd == cmd_types.REGISTER:
                        args = request.args
                        pubKey = get_pubKey(args)
                        register(usr_ip, conn, pubKey)
                    elif cmd == cmd_types.NEW_MSG:
                        #TODO
                        continue
                    elif cmd == cmd_types.SEND_FRG:
                        #TODO
                        continue
                    elif cmd == cmd_types.SEND_PLAINTEXT:
                        args = request.args
                        msg_received = args['msg']
                        print("<" + usr_ip + "> " + msg_received)
                        # Calls broadcast function to send message to all
                        message_to_send = "<" + usr_ip + "> " + msg_received
                        broadcast(message_to_send, conn)
                    elif cmd == cmd_types.USER_EXT:
                        print("I'm removing a client")
                        remove(usr_ip, conn)
                        #TODO
                        continue
                    else:
                       print("Invalid command received")
                else:
                    """message may have no content if the connection
                    is broken, in this case we remove the connection"""
                    remove(conn)
 
            except:
                print("MAIN ERROR")
                continue
 
def broadcast(message, connection):
    """Using the below function, we broadcast the message to all
    clients who's object is not the same as the one sending
    the message """
    for clients in list_of_clients:
        if clients!=connection:
            try:
                clients
                clients.send(message.encode(ENCODING))
            except:
                clients.close()
 
                # if the link is broken, we remove the client
                remove(clients)

def notify_user(cmd, user_id, npk):
    #TODO
    return

def get_pubKey(args):
    '''
        Get the publicKey from the user passed args
    '''
    config.set_default_curve()
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

def register(ip, conn, pubkey):
    global ip_to_id
    usr_id = get_id()
    if ip in ip_to_id:
        print("Client already registered.")
    ip_to_id[ip] = (usr_id, pubkey, conn)
    return

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