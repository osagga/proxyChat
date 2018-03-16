class Node :
----

	ip_to_id = {} #Indexed by ip, returns (id,pk)
	key_fragment_arr = [[]] #Indexed by [from][to] contains corresponding fragment
	available_ids = [] #queue containing the available ids 
	usr_cmds = ['usr_send_msg', 'usr_send_frag' ,'usr_exit']
	node_cmds = ['node_new_user', 'node_new_msg']


def set_fragment(_from, to, frag):
	key_fragment_arr[_from][to] = frag

def remove(ip): 
'''
User of <ip> is remove from the chat 
'''
	rem_id = ip_to_id[ip]
	
	for _from in key_fragment_arr: 
		set_fragment(_from, rem_id, None)

	for usr in all_users:
		set_fragment(rem_id, usr, None)
	
	available_ids += [rem_id]

def register(ip, pubkey):
	

def notify_user(cmd, user_id, npk):

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	








