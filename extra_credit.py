import multiprocessing
import hashlib
import time



user = 'bucky,{}'
salt = '0719173488'.encode()
known_hash = 'fdd2a52969ff2cab2c2653e5cc7129a70b0cad398ea3ff44bf700bb0cd168d8b5c080c90b9281f04993b05895705229c3a5261e20f8a453369b81efd4f9040b6'

f = open('realhuman_phill.txt', 'r', encoding='utf-8', errors='ignore')

BASE_PASSWORDS = 63_941_069
CPUS = multiprocessing.cpu_count()
BATCH_SIZE = int(BASE_PASSWORDS / CPUS)

def validate(password):
    lo, hi, dt, sm = 0, 0, 0, 0

    if len(password) < 6:
        return False

    for c in password:
        lo |= c.islower()
        hi |= c.isupper()
        dt |= c.isdigit()
        sm |= (1 ^ c.isalnum())
    
    return lo + hi + sm + dt >= 3

def scan_password(n, data, progress, res):
    for password in data:
        if not validate(password):
            continue
        
        h = hashlib.scrypt(password=user.format(password).encode(), salt=salt, n=16, r=32, p=1).hex()
        if h == known_hash:
            for i in range(len(password)):
                res[i] = ord(password[i])
            res[len(password)] = ord('\0')
            progress[n] = -1
            break
        progress[n] += 1

def out(res):
    print('\nFound Password:', end=' ')
    for c in res:
        if c == b'\x00':
            print()
            break
        print(c.decode('utf-8'), end='')

progress = multiprocessing.Array('i', CPUS) # shared mem so each process can report progress
res = multiprocessing.Array('c', 64) # result array with password
print("Starting search on %d CPUs, BATCH_SIZE=%d." % (CPUS, BATCH_SIZE))

for i in range(CPUS):
    #Build process data chunk
    passw_chunk = []
    for j in range(BATCH_SIZE):
        passw_chunk.append(f.readline().strip())

    #Start search job
    p = multiprocessing.Process(target=scan_password, args=(i, passw_chunk, progress, res))
    p.daemon = True
    p.start()

f.close()

while 1:
    iterations = 0
    for prog in progress:
        if prog == -1: #Termination condition ( a password has been found )
            out(res)
            exit()
        iterations += prog
    print("Approximate progress: %.2f%%\tPasswords scanned: %d" % (iterations/BASE_PASSWORDS*100, iterations), end='\r')
    time.sleep(1)
