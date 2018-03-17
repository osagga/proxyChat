#! /usr/bin/env python3

class key_frag_map:

    def __init__(self, NUM_CLIENTS):
        self.key_fragment_arr = [[None for i in range(NUM_CLIENTS)] for j in range(NUM_CLIENTS)]
    
    def set_fragment(self, _from, to, frag):
        self.key_fragment_arr[_from][to] = frag
        return

    def get_fragment(self, _from, to):
        return self.key_fragment_arr[_from][to]
    
    
