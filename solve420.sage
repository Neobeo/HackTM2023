from pwn import *
from hashlib import sha256
from subprocess import check_output
from re import findall
from time import time

q = 8383489
F.<x> = GF(q)[]

sh = process(['sage', 'glp420.sage'])
def get():
    tmp = bytes.fromhex(sh.readline().decode().split()[-1])
    return F([int.from_bytes(tmp[i:i+3],'big') for i in range(0,len(tmp),3)])
a = get()
t = get()

##################################################

def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = '[[' + ']\n['.join(' '.join(map(str,row)) for row in M) + ']]'
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int,findall(b'-?\\d+', ret)))

def solve(poly):
    n = poly.degree()
    to_remove = range(n, n*4/3)
    t0 = time()
    main_block = matrix([vector(a*x^i%poly) for i in range(n)])
    mat = block_matrix(ZZ, [[1,-main_block,0],[0,q,0],[0,matrix(vector(t%poly)),matrix([[q]])]])
    mat = mat.delete_columns(to_remove).delete_rows(to_remove)
    ret = flatter(mat)[-1]
    print(f'{mat.nrows()}x{mat.ncols()} lattice reduced in {time()-t0}')
    return F(list(ret[:n]))

ps = [
    (x^48 - x^46 + x^38 - x^36 + x^34 - x^32 + x^28 - x^26 + x^24 - x^22 + x^20 - x^16 + x^14 - x^12 + x^10 - x^2 + 1),
    (x^48 + x^46 - x^38 - x^36 - x^34 - x^32 + x^28 + x^26 + x^24 + x^22 + x^20 - x^16 - x^14 - x^12 - x^10 + x^2 + 1),
    (x^48 - x^47 + x^46 + x^43 - x^42 + 2*x^41 - x^40 + x^39 + x^36 - x^35 + x^34 - x^33 + x^32 - x^31 - x^28 - x^26 - x^24 - x^22 - x^20 - x^17 + x^16 - x^15 + x^14 - x^13 + x^12 + x^9 - x^8 + 2*x^7 - x^6 + x^5 + x^2 - x + 1),
    (x^48 + x^47 + x^46 - x^43 - x^42 - 2*x^41 - x^40 - x^39 + x^36 + x^35 + x^34 + x^33 + x^32 + x^31 - x^28 - x^26 - x^24 - x^22 - x^20 + x^17 + x^16 + x^15 + x^14 + x^13 + x^12 - x^9 - x^8 - 2*x^7 - x^6 - x^5 + x^2 + x + 1),
    (x^60 - 1),
    (x^72 + x^60 + x^48 + x^36 + x^24 + x^12 + 1),
    (x^96 - x^94 + x^92 + x^86 - x^84 + 2*x^82 - x^80 + x^78 + x^72 - x^70 + x^68 - x^66 + x^64 - x^62 - x^56 - x^52 - x^48 - x^44 - x^40 - x^34 + x^32 - x^30 + x^28 - x^26 + x^24 + x^18 - x^16 + 2*x^14 - x^12 + x^10 + x^4 - x^2 + 1),
    ]
prod = lcm(ps)
assert prod == x^420-1
rs = list(map(solve, ps))

s = crt(rs, ps)
e = (t-a*s) % prod
assert all(c in {0,1,q-1} for c in s)
assert all(c in {0,1,q-1} for c in e)

##################################################

c = F.quo(prod)(sum(v*x^i for i,v in enumerate(bits(sha256(bytes(1260) + b"sign me!").digest())[::-1])))
for z in s*c, e*c, c:
    sh.sendline(b''.join(int(z[i]).to_bytes(3, 'big') for i in range(420)).hex().encode())
print(sh.readall().decode())