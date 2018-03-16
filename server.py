# Python program to implement server side of chat room.
from socket import socket, SOL_SOCKET, SO_REUSEADDR, AF_INET, SOCK_STREAM
from request import Request
import select
import sys
import queue
from threading import Thread
from umbral import keys

ENCODING = "utf-8"
NUM_CLIENTS = 100
BUFFER_SIZE = 2048
REGISTER = 'node_new_user'
NEW_MSG = 'node_new_msg'
# SEND_MSG = 'usr_send_msg'
SEND_FRG = 'usr_send_frag'
USER_EXT = 'usr_exit'

ip_to_id = {} #Indexed by ip, returns (id,pk)
key_fragment_arr = [[None for i in range(NUM_CLIENTS)] for j in range(NUM_CLIENTS)] #Indexed by [from][to] contains corresponding fragment
available_ids = queue.Queue() #queue containing the available ids
list_of_clients = []

def clientthread(conn, addr):
    # sends a message to the client whose user object is conn
    conn.send("Welcome to this chatroom!".encode(ENCODING))
 
    while True:
            try:
                # Make sure that encoding will not violate the check on `message` below
                message = conn.recv(BUFFER_SIZE)
                if message:
                    # Parse command
                    try:
                        request = Request.deserialize(message)
                    except:
                        print("THIS IS AN ERROR")

                    print("The request I got is as follow {0}".format(request))
                    cmd = request.cmd
                    if cmd == REGISTER:
                        print("I'm now in Register")
                        ip = addr[0]
                        args = request.args
                        pubKey = get_pubKey(args)
                        register(ip, pubKey)
                    elif cmd == NEW_MSG:
                        #TODO
                        continue
                    elif cmd == SEND_FRG:
                        #TODO
                        continue
                    elif cmd == USER_EXT:
                        #TODO
                        continue
                    else:
                        # IF Add
                        print("<" + addr[0] + "> " + message)
                        # Calls broadcast function to send message to all
                        message_to_send = "<" + addr[0] + "> " + message
                        broadcast(message_to_send, conn)
                else:
                    """message may have no content if the connection
                    is broken, in this case we remove the connection"""
                    remove(conn)
 
            except:
                continue
 
def broadcast(message, connection):
    """Using the below function, we broadcast the message to all
    clients who's object is not the same as the one sending
    the message """
    for clients in list_of_clients:
        if clients!=connection:
            try:
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
    if 'pub_key' in args:
        return keys.UmbralPublicKey.from_bytes(args['pub_key'])
    else:
        raise ValueError("Can't find user PublicKey")

# def remove(ip): 
# '''
# User of <ip> is remove from the chat 
# '''
# 	rem_id = ip_to_id[ip]
	
# 	for _from in key_fragment_arr: 
# 		set_fragment(_from, rem_id, None)

# 	for usr in all_users:
# 		set_fragment(rem_id, usr, None)
	
# 	available_ids += [rem_id]

def remove(connection):
    """The following function simply removes the object
    from the list that was created at the beginning of 
    the program"""
    if connection in list_of_clients:
        list_of_clients.remove(connection)
    return

def register(ip, pubkey):
    #TODO
    print("I'm adding a user to the set!!")
 
def set_fragment(_from, to, frag):
    """
        The following function adds the given key frag 
        to the appropiate position in the frag dict
    """
    key_fragment_arr[_from][to] = frag
    return

def main():
    """The first argument AF_INET is the address domain of the
    socket. This is used when we have an Internet Domain with
    any two hosts The second argument is the type of socket.
    SOCK_STREAM means that data or characters are read in
    a continuous flow."""
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