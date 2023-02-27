import hashlib
import math
#print(hashlib.sha256("user,12345,999999".encode()).hexdigest())


known_passw = {
    'bjacobsen': {
        "input": 'bjacobsen,{},980166',
        'hash': 'ffa2dcdd84a45582b17d4f535cda63887273f34a679eded10428b480999c3a8b'
    },
    'cecio':{
        'input': 'ceccio,{},547750',
        'hash': '41db4f70c8ce1c866462b4c0636aef38c1ea5ef36809bf099165c826bc3a8881'
    }
}
def crack(n):
    '''
    Checks all passwords for length n where hashed passw = known passw
    '''
    max_val = '9'*n
    res = []
    for i in range(int(max_val)):
        passw = str(i)
        passw = passw.zfill(n)

        for key in known_passw.keys():
            hashed = hashlib.sha256(known_passw[key]['input'].format(passw).encode()).hexdigest()
            if hashed == known_passw[key]['hash']:
                res.append((key, passw))
    return res


#for i in range(1, 9):
print(crack(8))